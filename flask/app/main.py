from flask import Flask, render_template, request, session, logging, url_for, redirect, flash
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
# from app import app
# from passlib.hash import sha256_crypt
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.secret_key = 'muhammad farhan simatupang docker project'
app.config["MYSQL_ROOT_PASSWORD"]='1234'
# app.config["MYSQL_ROOT_DATABASE_URL"]='mysql+pymysql://root:@localhost:3306/userlogin'
app.config["MYSQL_USER"]='farhan'
app.config["MYSQL_PASSWORD"]='farhan2001'

engine = create_engine("mysql+pymysql://root:@localhost:3306/userlogin")
# engine = create_engine(" mysql+pymysql://root@localhost/userslogin ")
db = scoped_session(sessionmaker(bind=engine))

# db = SQLAlchemy(app)

@app.route('/')
def home():
    return render_template("home.html")

@app.route('/home')
def home_():
    return render_template("home.html")

#register
@app.route("/register", methods = ["GET","POST"])
def register():
    
    if request.method =="POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm = request.form.get("confirm")

        if password != confirm:
            flash("Password doesn't match","danger")
            return render_template("register.html")
        
        usernamedata = db.execute("SELECT username FROM users WHERE username =:username",{"username":username}).fetchone()
        emaildata = db.execute("SELECT email FROM users WHERE email =:email",{"email":email}).fetchone()

        if usernamedata is not None:
            if emaildata is not None:
                flash("Username or email has been taken, choose another one","danger")
                return render_template("register.html")
            flash("Username or email has been taken, choose another one","danger")
            return render_template("register.html")

        else:
            secure_password = generate_password_hash(str(password))
            db.execute("INSERT INTO users (username, email, password) VALUES(:username, :email, :password)",{"username":username, "email":email, "password": secure_password})
            db.commit()
            flash("You are now registered and can login","success")
            return redirect(url_for('login'))
        

    return render_template("register.html")

#login
@app.route("/login", methods = ["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        usernamedata = db.execute("SELECT username FROM users WHERE username =:username",{"username":username}).fetchone()
        passworddata = db.execute("SELECT password FROM users WHERE username =:username",{"username":username}).fetchone()

        if usernamedata is None:
            flash("Username or Password is incorrect","danger")
            # return render_template("login")

        else:
            if check_password_hash(passworddata['password'],password):
                session["log"]=True

                flash("You are now logged in","success")
                return redirect(url_for("content"))

            else:
                flash("Username or Password is incorrect","danger")
                return render_template("login.html")

    return render_template("login.html")

@app.route('/content')
def content():
    return render_template("content.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Goodbye friend, have a nice day")
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
