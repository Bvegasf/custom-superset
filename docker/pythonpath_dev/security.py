from flask import redirect, g, flash, request
from flask_appbuilder.security.views import UserLDAPModelView,AuthLDAPView
from superset.security import SupersetSecurityManager
from flask_appbuilder.security.views import expose
from flask_appbuilder.security.manager import BaseSecurityManager
from flask_login import login_user, logout_user
import ldap
import logging
from superset_config import AUTH_LDAP_SERVER

log = logging.getLogger(__name__)

class CustomAuthLDAPView(AuthLDAPView):
    login_template = "appbuilder/general/security/login_ldap.html"

    @expose('/login/', methods=['GET', 'POST'])
    def login(self):
        redirect_url = self.appbuilder.get_url_for_index

        if request.args.get('username') is not None:
            if request.args.get('redirect') is not None:
                redirect_url = request.args.get('redirect') 
            username = request.args.get('username')
            user = self.appbuilder.sm.find_user(username)
            log.info("userdb -> " + repr(user))
            if user:
                login_user(user, remember=False)
            else:
                con = ldap.initialize(AUTH_LDAP_SERVER)
                user_dn, user_attributes = self.appbuilder.sm._search_ldap(ldap, con, username)
                log.warning("user ldap -> " + repr(user_dn))
                # If the user is new, register them
                if user_dn and user_attributes and self.appbuilder.sm.auth_user_registration:
                    user = self.appbuilder.sm.add_user(
                        username=username,
                        first_name=self.appbuilder.sm.ldap_extract(
                            user_attributes, self.appbuilder.sm.auth_ldap_firstname_field, ""
                        ),
                        last_name=self.appbuilder.sm.ldap_extract(
                            user_attributes, self.appbuilder.sm.auth_ldap_lastname_field, ""
                        ),
                        email=self.appbuilder.sm.ldap_extract(
                            user_attributes,
                            self.appbuilder.sm.auth_ldap_email_field,
                            username,
                        ),
                        role=self.appbuilder.sm._ldap_calculate_user_roles(user_attributes),
                    )
                    log.debug("New user registered: {0}".format(user))

                    # If user registration failed, go away
                    if not user:
                        log.info(LOGMSG_ERR_SEC_ADD_REGISTER_USER.format(username))
                        return super(CustomAuthLDAPView,self).login()
                    # self.appbuilder.sm.update_user_auth_stat(user)
                    login_user(user, remember=False)
            return redirect(redirect_url)
        elif g.user is not None and g.user.is_authenticated:
            return redirect(redirect_url)
        else:
            flash('Unable to auto login', 'warning')
            return super(CustomAuthLDAPView,self).login()

class CustomSecurityManager(SupersetSecurityManager):
    authldapview = CustomAuthLDAPView
    def __init__(self, appbuilder):
        super(CustomSecurityManager, self).__init__(appbuilder)