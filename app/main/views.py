from datetime import datetime
from flask import render_template, session, redirect, url_for
from flask.ext.login import login_required

from . import main


@main.route('/', methods=['GET', 'POST'])
@login_required
def index():
    return render_template('index.html')
