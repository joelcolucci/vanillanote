Vanilla Note | Note Taking Web Application
=====================
###Nanodegree Project
School: Udacity

Program: Full Stack Web Developer Nanodegree

Project #3

Supporting course(s):

[Full Stack Foundations](https://www.udacity.com/course/viewer#!/c-ud088)

[Authentication & Authorization: OAuth](https://www.udacity.com/course/viewer#!/c-ud330)

###Project Overview
You will develop an application that provides a list of items within a variety of categories as well as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own items.

###Attention: Please Note
This project implements the idea of a "catolog of items" in the form of a note taking application. Instead of a list of categories with items within each category, a user has a list of notebooks with a list of notes within each notebook.

#####Equivalencies
Category = Notebook

Items = Notes

#####Currently Deployed on Heroku
Project deployed: [vanillanote.herokuapp.com](vanillanote.herokuapp.com)

Note: Changes are required to app.py in order to run as a local Flask app.

###Project Depencies
- Flask v0.9
- Flask-Login v0.1.3
- gunicorn v19.3.0
- httplib2 v0.9.1
- itsdangerous v0.24
- Jinja2 v2.7.3
- MarkupSafe v0.23
- oauth2client v1.4.9
- psycopg2 v2.6
- pyasn1 v0.1.7
- pyasn1-modules v0.0.5
- requests v2.7.0
- rsa v3.1.4
- six v1.9.0
- SQLAlchemy v0.7.4
- Werkzeug v0.8.3
- PostgreSQL v9.4.1

###How To Use
0. Install dependencies
1. Download or clone this repository
2. Add the following code to the bottom of app.py
```python
if __name__ == '__main__':
    app.secret_key = 'my super secret key'
    app.debug = True
    app.run(host = '0.0.0.0', port = 5000)
```
3. Add desired path to postgres db on line 66 in db_setup.py
4. Add desired path to postgres db on line 31 in db_setup.py
5. Execute db_setup.py from command line
6. Execute app.py from command line

####Resources
All resources used/referenced are listed in the file resources.txt.