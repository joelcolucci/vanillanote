import os
import random
import string

from flask import Flask, render_template, request, url_for, redirect
from flask import session as login_session
from flask import make_response

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import requests
import json


from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db_setup import Base, Notebooks


app = Flask(__name__)
app.debug = True
app.secret_key = 'super_secret'


# Connect to Database and create database session
engine = create_engine('postgres://thyucdfobkhbyq:Kwj60OMjv2z7ovelhZet-OWYzq@ec2-107-20-222-114.compute-1.amazonaws.com:5432/dci4hqej3ncibd')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))

    login_session['state'] = state

    # return "The current session state is %s" % login_session['state']
    return state
    # return render_template('login.html', STATE=state)


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/notebook/new', methods=['GET','POST'])
def newNotebook():
    if request.method == 'POST':
        new_notebook = Notebooks(name="Sample")

        session.add(new_notebook)
        session.commit()

        return redirect(url_for('home'))

    else:
        return render_template('new_notebook.html')
