import os
import random
import string
import logging

from flask import Flask, render_template, request, url_for, redirect, jsonify, flash
from flask import session as login_session
from flask import make_response

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import requests
import json

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db_setup import Base, Notebook, Note, User


app = Flask(__name__)
app.debug = True
app.secret_key = 'super_secret'

CLIENT_ID = json.loads(
    open('client_secret.json', 'r').read())['web']['client_id']

APPLICATION_NAME = "Vanilla Note"

# Connect to Database and create database session
engine = create_engine('postgres://thyucdfobkhbyq:Kwj60OMjv2z7ovelhZet-OWYzq@ec2-107-20-222-114.compute-1.amazonaws.com:5432/dci4hqej3ncibd')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/')
@app.route('/notebooks')
def showLogin():
    if 'username' not in login_session:
        state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
        login_session['state'] = state
        # return "The current session state is %s" % login_session['state']
        return render_template('login.html', STATE=state)

    notebooks = session.query(Notebook).all()
    return render_template('view_notebooks.html', notebooks=notebooks)


@app.route('/notebook/new', methods=['GET','POST'])
def newNotebook():
    # If user not logged in redirect back to home
    if 'username' not in login_session:
        return redirect('/')

    if request.method == 'POST':
        title = request.form.get('title', 'title')
        new_notebook = Notebook(name=title)

        session.add(new_notebook)
        session.commit()

        return redirect(url_for('showLogin'))

    else:
        return render_template('view_new_notebook.html')


@app.route('/notebook/delete/<int:notebook_id>/', methods=['POST'])
def deleteNotebook(notebook_id):
    # If user not logged in redirect back to home
    if 'username' not in login_session:
        return redirect('/')

    if request.method == 'POST':
        notebook = session.query(Notebook).filter_by(id=notebook_id).one()

        session.delete(notebook)
        session.commit()

        return redirect(url_for('showLogin'))

    else:
        return render_template('view_notebooks.html')

@app.route("/notebook/<int:notebook_id>/notes", methods=['GET'])
@app.route('/notebook/<int:notebook_id>/notes/new', methods=['GET','POST'])
def newNote(notebook_id):
    # If user not logged in redirect back to home
    if 'username' not in login_session:
        return redirect('/')

    if request.method == 'POST':
        title = request.form.get('title', "No named note")
        content = request.form.get('content', 'hello, world')

        note = Note(title=title, content=content, notebook_id=notebook_id)

        # Add note to database
        session.add(note)

        # Flush so we can ask the unique ID assigned to the new note.
        session.flush()
        session.commit()

        # Get the unique ID of the note after flush.
        note_id = note.id

        return redirect(url_for('viewNote', notebook_id=notebook_id, note_id=note_id))

    else:
        notes = session.query(Note).filter_by(notebook_id=notebook_id).all()
        return render_template('view_new_note.html', notes=notes, notebook_id=notebook_id)



@app.route('/notebook/<int:notebook_id>/notes/<int:note_id>', methods=['GET'])
def viewNote(notebook_id, note_id):
    # If user not logged in redirect back to home
    if 'username' not in login_session:
        return redirect('/')

    notes = session.query(Note).filter_by(notebook_id=notebook_id).all()

    note = session.query(Note).filter_by(id=note_id).one()

    return render_template('view_notes.html', notes=notes, notebook_id=notebook_id, note=note)



@app.route('/notebook/<int:notebook_id>/notes/<int:note_id>/edit', methods=['POST'])
def editNote(notebook_id, note_id):
    # If user not logged in redirect back to home
    if 'username' not in login_session:
        return redirect('/')

    if request.method == 'POST':
        note = session.query(Note).filter_by(id=note_id).one()
        note.title = request.form.get('title')
        note.content = request.form.get('content')


        return redirect(url_for('viewNote', notebook_id=notebook_id, note_id=note_id))


@app.route('/notebook/<int:notebook_id>/notes/<int:note_id>/delete', methods=['POST'])
def deleteNote(notebook_id, note_id):
    # If user not logged in redirect back to home
    if 'username' not in login_session:
        return redirect('/')

    if request.method == 'POST':
        note = session.query(Note).filter_by(id=note_id).one()

        session.delete(note)
        session.commit()

        return redirect(url_for('showLogin'))



@app.route('/gconnect', methods=['POST'])
def gconnect():
    # When the client first requested the page we generated the "state" token
    # and sent it as part of the HTML. We included it in our JavaScript callback
    # function.
    # 1. Page loads
    # 2. User clicks login with Google plus
    # 3. A request is sent from the client to Google
    # 4. Google asks users to confirm they are requesting a token
    #    to give Vanilla Note access to xyz
    # 5. User accepts
    # 6. Google sends token back to client which then calls the callback function
    # 7. The callback function sends the data received from Google to the server
    #    via AJAX
    # 8. Here we are handling that AJAX

    # Validate the "state" token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'

        return response
    
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)

    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'

        return response

    # # Check that the access token is valid by running it against their oauth
    # # API.
    access_token = credentials.access_token

    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)

    h = httplib2.Http()

    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']

    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'

        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."

        response.headers['Content-Type'] = 'application/json'
        
        return response

    # Get stored_credentials. Note this may return None if the user has
    # never connected. We know this and handle it below.
    stored_credentials = login_session.get('credentials')

    stored_gplus_id = login_session.get('gplus_id')
    
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    login_session['credentials'] = credentials # ERROR: THIS LINE IS causing "not JSON serializeable"
    login_session['gplus_id'] = gplus_id

    # Get user info via a request to google, server to server, mono e mono.
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


#DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')

    if credentials is None:
        # No user logged in but they somehow clicked "logoout" anyways
        response = make_response(
            json.dumps('Current user not connected.'), 401)

        response.headers['Content-Type'] = 'application/json'
        
        return response
    
    # Time to go ahead and log out the user by two doing things
    # First we will make an API call to tell Google get rid of the
    # token you gave us
    # Second we delete the session records on our end
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    # Check that Googles reponse to us is a-okay
    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'

        return response

    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))

        response.headers['Content-Type'] = 'application/json'

        return response
