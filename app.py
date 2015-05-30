import os
import random

import string

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

# Connect to Heroku database
engine = create_engine('postgres://thyucdfobkhbyq:Kwj60OMjv2z7ovelhZet-OWYzq@ec2-107-20-222-114.compute-1.amazonaws.com:5432/dci4hqej3ncibd')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/')
@app.route('/notebooks')
def showLogin():
    # If no user is logged in redirect back to login page.
    if 'username' not in login_session:
        # Create anti-forgery state token.
        state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
        login_session['state'] = state

        return render_template('view_login.html', STATE=state)

    user_id = login_session['user_id']

    # Query for all notebooks owned by user.
    notebooks = session.query(Notebook).filter_by(user_id=user_id).all()

    return render_template('view_notebooks.html', notebooks=notebooks)


@app.route('/notebook/new', methods=['GET', 'POST'])
def newNotebook():
    # If no user is logged in redirect back to login page.
    if 'username' not in login_session:
        return redirect('/')

    if request.method == 'POST':
        # Extract form values from request object.
        title = request.form.get('title', 'title')

        # Create new notebook object.
        new_notebook = Notebook(name=title,
                                user_id=login_session['user_id'])

        # Store notebook in database.
        session.add(new_notebook)
        session.commit()

        # Notify user action successful.
        flash('New notebook "%s" succesfully created!' % new_notebook.name)
        return redirect(url_for('showLogin'))
    else:
        return render_template('view_new_notebook.html')


@app.route('/notebook/<int:notebook_id>/edit', methods=['GET', 'POST'])
def editNotebook(notebook_id):
    # If no user is logged in redirect back to login page.
    if 'username' not in login_session:
        return redirect('/')

    # Query for notebook by notebook id passed in via path.
    notebook = session.query(Notebook).filter_by(id=notebook_id).one()

    # Verify that user owns notebook they are attempting to access.
    if notebook.user_id != login_session['user_id']:
        # Notify user they do not have permission to access.
        flash('You do not have permission!')
        return redirect(url_for('showLogin'))

    if request.method == 'POST':
         # Extract form values from request object and update record in db.
        notebook.name = request.form.get('title')

        # Notify user action successful.
        flash('Notebook "%s" succesfully updated!' % notebook.name)
        return redirect(url_for('showLogin'))
    else:
        return render_template('view_edit_notebook.html', notebook=notebook)


@app.route('/notebook/<int:notebook_id>/delete', methods=['GET', 'POST'])
def deleteNotebook(notebook_id):
    # If no user is logged in redirect back to login page.
    if 'username' not in login_session:
        return redirect('/')

    # Query for notebook by notebook id passed in via path.
    notebook = session.query(Notebook).filter_by(id=notebook_id).one()

    # Verify that user owns notebook they are attempting to access.
    if notebook.user_id != login_session['user_id']:
        # Notify user they do not have permission to access.
        flash('You do not have permission!')
        return redirect(url_for('showLogin'))

    if request.method == 'POST':
        # Delete notebook from database.
        session.delete(notebook)
        session.commit()

        # Notify user action successful.
        flash('Notebook "%s" successfully deleted!' % notebook.name)
        return redirect(url_for('showLogin'))
    else:
        # Show modal containing prompt to confirm delete action.
        return render_template('view_notebooks.html', show_modal=True)


@app.route("/notebook/<int:notebook_id>/notes", methods=['GET'])
@app.route('/notebook/<int:notebook_id>/notes/new', methods=['GET', 'POST'])
def newNote(notebook_id):
    # If no user is logged in redirect back to login page.
    if 'username' not in login_session:
        return redirect('/')

    # Query for notebook by notebook id passed in via path.
    notebook = session.query(Notebook).filter_by(id=notebook_id).one()

    # Verify that user owns notebook they are attempting to access.
    if notebook.user_id != login_session['user_id']:
        # Notify user they do not have permission to access.
        flash('You do not have permission!')
        return redirect(url_for('showLogin'))

    if request.method == 'POST':
        # Extract form values from request object.
        title = request.form.get('title', "No named note")
        content = request.form.get('content', 'hello, world')

        # Create new note object.
        note = Note(title=title, content=content, notebook_id=notebook_id,
                    user_id=login_session['user_id'])

        # Add note to database
        session.add(note)
        session.commit()

        # We can only accesss auto generated 'id' property after committing
        # note to db.
        note_id = note.id

        # Notify user action successful.
        flash('New note "%s" succesfully created!' % note.title)

        # Render template for note that was just created.
        return redirect(url_for('viewNote', notebook_id=notebook_id, note_id=note_id))
    else:
        # Query for all notes for notebook id pass in via path.
        notes = session.query(Note).filter_by(notebook_id=notebook_id).all()
        return render_template('view_new_note.html', notes=notes, notebook_id=notebook_id)


@app.route('/notebook/<int:notebook_id>/notes/<int:note_id>', methods=['GET'])
def viewNote(notebook_id, note_id):
    # If no user is logged in redirect back to login page.
    if 'username' not in login_session:
        return redirect('/')

    # Query for all notes related to notebook id.
    notes = session.query(Note).filter_by(notebook_id=notebook_id).all()

    # Query for note by note id passed in via path.
    note = session.query(Note).filter_by(id=note_id).one()

    # Verify that user owns note they are attempting to access.
    if note.user_id != login_session['user_id']:
        # Notify user they do not have permission to access.
        flash('You do not have permission!')
        return redirect(url_for('showLogin'))

    return render_template('view_notes.html', notes=notes, notebook_id=notebook_id, note=note)


@app.route('/notebook/<int:notebook_id>/notes/<int:note_id>/edit', methods=['POST'])
def editNote(notebook_id, note_id):
    # If no user is logged in redirect back to login page.
    if 'username' not in login_session:
        return redirect('/')

    # Query for note by note id passed in via path.
    note = session.query(Note).filter_by(id=note_id).one()

    # Verify that user owns note they are attempting to access.
    if note.user_id != login_session['user_id']:
        # Notify user they do not have permission to access.
        flash('You do not have permission!')
        return redirect(url_for('showLogin'))

    if request.method == 'POST':
        # Extract form values from request object and update records in db.
        note.title = request.form.get('title')
        note.content = request.form.get('content')

        # Notify user action successful.
        flash('Note "%s" succesfully updated!' % note.title)
        return redirect(url_for('viewNote', notebook_id=notebook_id, note_id=note_id))


@app.route('/notebook/<int:notebook_id>/notes/<int:note_id>/delete', methods=['GET', 'POST'])
def deleteNote(notebook_id, note_id):
    # If no user is logged in redirect back to login page.
    if 'username' not in login_session:
        return redirect('/')

    # Query for all notes related to notebook id.
    notes = session.query(Note).filter_by(notebook_id=notebook_id).all()

    # Query for note by note id passed in via path.
    note = session.query(Note).filter_by(id=note_id).one()

    # Verify that user owns note they are attempting to access.
    if note.user_id != login_session['user_id']:
        # Does not have permission to edit, view or delete
        flash('You do not have permission!')
        return redirect(url_for('showLogin'))

    if request.method == 'POST':
        # Delete note from database.
        session.delete(note)
        session.commit()

        # Notify user action successful.
        flash('Note "%s" succesfully deleted!' % note.title)
        return redirect(url_for('newNote', notebook_id=notebook_id))

    else:
        # Show modal containing prompt to confirm delete action.
        return render_template('view_notes.html',
                                notes=notes,
                                notebook_id=notebook_id,
                                note=note,
                                show_modal=True)


def createUser(login_session):
    """Add new user to database and return user id."""
    # Create new user object.
    new_user = User(name=login_session['username'],
                    email=login_session['email'],
                    picture=login_session['picture'])

    # Add user to database.
    session.add(new_user)
    session.commit()

    # We can only accesss auto generated 'id' property after committing
    # user to db.
    user_id = new_user.id
    return user_id


def getUserInfo(user_id):
    """Get user info from database."""
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    """Return user id by querying on email address"""
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/data.json', methods=['GET'])
def jsonDataAll():
    # If no user is logged in redirect back to login page.
    if 'username' not in login_session:
        return redirect('/')

    user_id = login_session['user_id']

    # Query all notebooks owned by user_id.
    notebooks = session.query(Notebook).filter_by(user_id=user_id).all()

    # Convert notebook objects to list of serialize representations.
    notebooks_list = [notebook.serialize for notebook in notebooks]
    notebooks_dict = {}

    # Convert list of notebook objects into dict of notebook objs.
    for notebook in notebooks_list:
        notebooks_dict[notebook['id']] = notebook

    # Query all notes owned by user_id.
    notes = session.query(Note).filter_by(user_id=user_id).all()

    # Get serialized note and add each note to appropriate notebook.
    for note in notes:
        note_dict = note.serialize

        nb_id = note_dict['notebook_id']
        if nb_id in notebooks_dict:
            notebooks_dict[nb_id]['notes'].append(note_dict)

    return jsonify(notebooks=notebooks_dict)


@app.route('/notebook/<int:notebook_id>/data.json', methods=['GET'])
def jsonDataNotebook(notebook_id):
    # If no user is logged in redirect back to login page.
    if 'username' not in login_session:
        return redirect('/')

    # Query for notebook id owned by user_id.
    notebook = session.query(Notebook).filter_by(id=notebook_id).one()

    # Verify that user owns note they are attempting to access.
    if notebook.user_id != login_session['user_id']:
        # Does not have permission to edit, view or delete
        flash('You do not have permission!')
        return redirect(url_for('showLogin'))

    # Query for all notes by notebook id.
    notes = session.query(Note).filter_by(notebook_id=notebook_id).all()
    note_list = [note.serialize for note in notes]

    # Get notebook object as dict.
    notebook_dict = notebook.serialize

    # Add notes.
    notebook_dict['notes'] = note_list

    return jsonify(notebook=notebook_dict)


@app.route('/notebook/<int:notebook_id>/notes/data.json', methods=['GET'])
def jsonDataNotes(notebook_id):
    # If no user is logged in redirect back to login page.
    if 'username' not in login_session:
        return redirect('/')

    # Query for notebook id owned by user_id.
    notebook = session.query(Notebook).filter_by(id=notebook_id).one()

    # Verify that user owns note they are attempting to access.
    if notebook.user_id != login_session['user_id']:
        # Does not have permission to edit, view or delete
        flash('You do not have permission!')
        return redirect(url_for('showLogin'))

    # Query for all notes by notebook id.
    notes = session.query(Note).filter_by(notebook_id=notebook_id).all()
    note_list = [note.serialize for note in notes]

    return jsonify(notes=note_list)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """Handle Google+ sign in token flow"""
    # Validate the "state" token.
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

    # Check that the access token is valid by running it against their oauth
    # API.
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

    # Store credentials and id in login session.
    login_session['credentials'] = credentials
    login_session['gplus_id'] = gplus_id

    # Get user info via a request to google, server to server, mono e mono.
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # Check if user exists, if not make a new one.
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)

    login_session['user_id'] = user_id

    # Generate html response. Will be handled by AJAX callback on client side.
    output = '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 30px; height: 30px;border-radius: 150px;"> '

    # Notify user everything went well with the sign in.
    flash("You are now logged in as %s!" % login_session['username'])

    return output


#DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    """Handle Google+ sign out token flow"""
    credentials = login_session.get('credentials')

    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)

        response.headers['Content-Type'] = 'application/json'
        return response

    # Request that Google revokes token for user
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    # Check that Googles received request to revoke and request completed
    # successfully.
    if result['status'] == '200':
        # Reset users session data.
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        # Notify user they were disconnected successfully.
        flash("Successfully disconnected!")
        return redirect(url_for('showLogin'))

    else:
        # Handle if request to revoke token failed.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'

        return response


@app.route('/forceout')
def forceOut():
    """Development use only, forces session properties to be cleared"""
    del login_session['credentials']
    del login_session['gplus_id']
    del login_session['username']
    del login_session['email']
    del login_session['picture']

    response = make_response(json.dumps('Successfully disconnected.'), 200)
    response.headers['Content-Type'] = 'application/json'

    return response
