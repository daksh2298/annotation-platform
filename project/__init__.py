from flask import *
from flask_httpauth import HTTPBasicAuth
from flask_cors import CORS
from utils.utils import unauthorized_access

import os

# template_dir = os.path.abspath('./project/view/templates')
# static_dir = os.path.abspath('./project/view/static')
# application = app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
application = app = Flask(__name__)
app.secret_key='hasoc2020'
CORS(app)
auth=HTTPBasicAuth()
@auth.error_handler
def custom_401():
    """
    This function is used to return the custom response for unauthorized access to the api.
    :return:
    JSON response with message, status, and code
    """
    return unauthorized_access()
import project.controller
import project.model

