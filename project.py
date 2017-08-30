#!/usr/bin/env python
from flask import Flask, render_template, request, redirect, abort
from flask import jsonify, url_for, flash, session, make_response, g
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, CategoryItem, User
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from flask_httpauth import HTTPBasicAuth
import json
import requests
from functools import wraps

auth = HTTPBasicAuth()
app = Flask(__name__)

path = os.path.dirname(__file__)

CLIENT_ID = json.loads(
    open( path + '/client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"


# Connect to Database and create database session
engine = create_engine('sqlite:///categories.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
db = DBSession()


def verifyUser(f):
    @wraps(f)
    def decorated_function(*args, **Kwargs):
        if session.get('user_id') is None:
            flash('You are not unauthorized to do this action , \
              please login first to be able to do that!')
            return redirect(url_for('showLogin'))
        return f(*args, **Kwargs)
    return decorated_function


@app.route('/')
@app.route('/categories')
def showCategories():
    createSession()
    categories = db.query(Category).all()
    return render_template('categories.html',
                           cats=categories,
                           user_id=session.get('user_id'),
                           STATE=session.get('state'))


def createSession():
    if session.get('state') is None:
        session['state'] = ''.join(
            random.choice(string.ascii_uppercase +
                          string.digits)
            for x in xrange(32))


@app.route('/category/<int:category_id>/edit', methods=["GET", "POST"])
@verifyUser
def editCategory(category_id):
    category = db.query(Category).filter_by(id=category_id).one_or_none()
    if category.user_id != getUserId():
        flash("You can't edit another user's category!")
        return redirect(url_for('showCategories'))
    if request.method == "POST":
        category.name = request.form['name']
        category.description = request.form['description']
        return redirect(url_for('showCategories'))
    return render_template("editCategory.html", category=category)


@app.route('/category/<int:category_id>/items', methods=['GET'])
@verifyUser
def showItems(category_id):
    createSession()
    category = db.query(Category).filter_by(id=category_id).one_or_none()
    items = db.query(CategoryItem).filter_by(category_id=category_id)
    return render_template('Items.html',
                           category=category,
                           items=items,
                           creator=session)


@app.route('/category/<int:category_id>/items.json', methods=['GET'])
def showItemsJSON(category_id):
    items = db.query(CategoryItem).filter_by(category_id=category_id).all()
    return jsonify(Items=[i.serialize for i in items])


@app.route('/category/<int:category_id>/items/add', methods=['GET', 'POST'])
@verifyUser
def addCatItem(category_id):
    category = db.query(Category).filter_by(id=category_id).one_or_none()
    if request.method == 'POST':
        newItem = CategoryItem(name=request.form['name'],
                               description=request.form['description'],
                               title=request.form['title'],
                               category_id=category_id,
                               user_id=getUserId())
        db.add(newItem)
        db.commit()
        flash('Item Created!')
        return redirect(url_for('showItems', category_id=category_id))
    else:
        return render_template('addCatItem.html', category_id=category_id)


# Edit a Category item
@app.route('/category/<int:category_id>/Items/<int:catitem_id>/edit',
           methods=['GET', 'POST'])
@verifyUser
def editCatItem(category_id, catitem_id):
    editedItem = db.query(CategoryItem).filter_by(id=catitem_id).one_or_none()
    category = db.query(Category).filter_by(id=category_id).one_or_none()
    if editedItem.user_id != getUserId():
        flash("You can't edit Items that you didn't create!")
        return redirect(url_for('showItems', category_id=category_id))
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['title']:
            editedItem.title = request.form['title']
        db.add(editedItem)
        db.commit()
        flash('Category Item Successfully Edited')
        return redirect(url_for('showItems', category_id=category_id))
    else:
        return render_template('editCatItem.html',
                               item=editedItem,
                               category_id=category_id,
                               item_id=catitem_id)


# Delete a menu item
@app.route('/category/<int:category_id>/Items/<int:catitem_id>/delete',
           methods=['GET', 'POST'])
@verifyUser
def deleteCatItem(category_id, catitem_id):
    itemtodelete = db.query(CategoryItem).filter_by(
        id=catitem_id).one_or_none()
    if itemtodelete.user_id != getUserId():
        flash("You can't delete Items that you didn't create!")
        return redirect(url_for('showItems', category_id=category_id))
    if request.method == 'POST':
        db.delete(itemtodelete)
        db.commit()
        flash('Category Item Successfully Deleted')
        return redirect(url_for('showItems', category_id=category_id))
    else:
        return render_template('deleteCatItem.html', item=itemtodelete)


@app.route('/category/<int:category_id>/delete', methods=["GET", "POST"])
@verifyUser
def deleteCategory(category_id):
    category = db.query(Category).filter_by(id=category_id).one_or_none()
    if category.user_id != getUserId():
        flash("You can't delete another user's category!")
        return redirect(url_for('showCategories'))
    if request.method == "POST":
        db.delete(category)
        db.commit()
        flash('category %s has been deleted!' % category.name)
        return redirect(url_for('showCategories'))
    return render_template('deleteCategory.html', category=category)


@app.route('/category/add', methods=["POST", "GET"])
@verifyUser
def addCategory():
    if request.method == "POST":
        category = Category(
            name=request.form['name'], description=request.form['description'],
            user_id=getUserId())
        db.add(category)
        db.commit()
        return redirect(url_for('showCategories'))
    return render_template("newCategory.html")


def getUserId():
    ''' This function returns the userId from the DB so I can use for the
        Authorization instead of use the Session Id which is big number '''
    sessionemail = session['email']
    user = db.query(User).filter_by(email=sessionemail).first()
    return user.id


@app.route('/categories.json')
def getCategoriesJSON():
    categoriesItems = db.query(CategoryItem).all()
    return jsonify(categoriesItems=[i.serialize for i in categoriesItems])

# Create anti-forgery state token


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    session['state'] = state
    # return "The current session state is %s" % session['state']
    return render_template('login.html', STATE=state)


def createUser():
    newuser = User(username=session['username'], email=session[
                   'email'], picture=session['picture'])
    user = db.query(User).filter_by(email=session['email']).first()
    if user is None:
        db.add(newuser)
        db.commit()
        return newuser.id
    return user.id


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

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
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = session.get('access_token')
    stored_gplus_id = session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:

        response = make_response(json.dumps
                                 ('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    session['access_token'] = credentials.access_token
    session['gplus_id'] = gplus_id
    session['user_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    session['username'] = data['name']
    session['picture'] = data['picture']
    session['email'] = data['email']

    createUser()
    output = ''
    output += '<h1>Welcome, '
    output += session['username']
    output += '!</h1>'
    output += '<img src="'
    output += session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;\
                 -webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % session['username'])
    return output


@app.route('/gdisconnect')
def gdisconnect():
    return logout()


def logout():
    msg = ''
    if session.get('access_token')is None:
        msg = 'Current user not connected'
        return msg
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % session.get(
        'access_token')
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del session['access_token']
        del session['gplus_id']
        del session['username']
        del session['picture']
        del session['email']
        del session['user_id']
        del session['state']
        return redirect(url_for('showCategories'))
    else:
        msg = 'Failed to revoke token for given user.' + \
            session.get('access_token')
        return msg


@auth.verify_password
def verify_password(username_or_token, password):
    # Try to see if it's a token first
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = db.query(User).filter_by(id=user_id).one_or_none()
    else:
        user = db.query(User).filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)

    if db.query(User).filter_by(username=username).first() is not None:
        user = db.query(User).filter_by(username=username).first()
        # , {'Location': url_for('get_user', id = user.id, _external = True)}
        return jsonify({'message': 'user already exists'}), 200

    user = User(username=username)
    user.hash_password(password)
    db.add(user)
    db.commit()
    # , {'Location': url_for('get_user', id = user.id, _external = True)}
    return jsonify({'username': user.username}), 201


if __name__ == "__main__":
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run('0.0.0.0', 5000)
