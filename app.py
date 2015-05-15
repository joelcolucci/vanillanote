import os
from flask import Flask, render_template, request, url_for, redirect

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db_setup import Base, Notebooks


app = Flask(__name__)


# Connect to Database and create database session
engine = create_engine('postgres://thyucdfobkhbyq:Kwj60OMjv2z7ovelhZet-OWYzq@ec2-107-20-222-114.compute-1.amazonaws.com:5432/dci4hqej3ncibd')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


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
        return render_template('home.html')
