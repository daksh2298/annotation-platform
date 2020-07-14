__author__ = 'Daksh Patel'

from flask import *

from project import auth
from project.model.tweetModel import *
from utils.utils import *
import logtrail

msg = 'Something went wrong'


@app.errorhandler(403)
def resource_not_found(e):
    return createResponse(status_value=False,
                          code=403,
                          message="You have been logged out for security reasons!",
                          result={})


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    global msg
    # print(username_or_token)
    user = User.verify_auth_token(username_or_token)
    if not user and password == "something":
        print('-------------here-------------')
        abort(403, description="You have been logged out for security reasons!")
    if not user:
        # try to authenticate with username/password
        user = User.objects(username=username_or_token).first()
        if not user or not user.verify_password(password):
            msg = 'Incorrect username of password!'
            print(msg)
            # g.msg = msg
            return False
        elif not user.active:
            msg = 'Username deactivated.\n Please contact SUPER ADMIN to reactivate!'
            # g.msg = msg
            print(msg)
            return False
        else:
            msg = 'Verification successful.'
            print(msg)
    g.user = user
    return True


@app.route('/login', methods=['POST'])
def login():
    global msg
    username = request.form.get('username')
    password = request.form.get('password')
    logtrail.Logger.info(f'Sign in attempt by {username}')
    flag = verify_password(
        username_or_token=username,
        password=password
        )
    logtrail.Logger.info(f'Sign in attempt status {flag}')
    if flag:
        user = g.user
        auth_token = user.auth_token
        user_role = user.roles
        name = user.name
        code = 200
        status = True
        result = {
            'name': name,
            'auth_token': auth_token,
            'user_role': user_role
            }
        logtrail.Logger.info(f'Sign in successful by {username}')
        resp = createResponse(
            status_value=status,
            code=code,
            message=msg,
            result=result
            )
        return resp
    else:
        code = 400
        status = False
        result = {}
        resp = createResponse(
            status_value=status,
            code=code,
            message=msg,
            result=result
            )
        logtrail.Logger.info(f'Sign in unsuccessful by {username}')
        return resp


@app.route('/logout', methods=['GET', 'POST'])
@auth.login_required
def logout():
    user = g.user
    user.set_new_auth_token()
    print('logged out')
    code = 200
    status = True
    result = {}
    msg="Successfully logged out!"
    resp = createResponse(
        status_value=status,
        code=code,
        message=msg,
        result=result
        )
    return resp
