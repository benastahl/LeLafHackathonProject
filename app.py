from flask import Flask, render_template, request, make_response, redirect
import mongoengine
import bcrypt
import secrets
import os
import certifi
from datetime import datetime
from dotenv import load_dotenv, find_dotenv

VALID_LEHIGH_VALLEY_ZIPCODES = [
    "18102", "18104", "18103", "18015", "18018", "18052", "18062", "18049",
    "18109", "18036", "18175", "18080", "18031", "18032", "18078", "18034",
    "18106", "18037", "18066", "18069", "18011", "18041", "18101", "19529",
    "18092", "18051", "18053", "18059", "18087", "18079", "18195", "18001",
    "18025", "18046", "18060", "18065", "18068", "18098", "18099", "18105"
]


def verify_zipcode(zipcode):
    return zipcode in VALID_LEHIGH_VALLEY_ZIPCODES


load_dotenv(find_dotenv())
app = Flask(__name__)
db_url = os.getenv("MONGO_DB")
db = mongoengine.connect(
    host=db_url,
    tlsCAFile=certifi.where()
)


class User(mongoengine.Document):
    email = mongoengine.StringField()
    username = mongoengine.StringField()
    zip_code = mongoengine.StringField()
    password = mongoengine.StringField()
    auth_token = mongoengine.StringField()

    created = mongoengine.DateTimeField()


class Post:
    def __init__(self, date, organization, location, date_posted, service_type, description):
        self.date = date
        self.organization = organization
        self.location = location
        self.date_posted = date_posted
        self.service_type = service_type
        self.description = description

@app.route("/", methods=["GET"])
def home():
    auth_token = request.cookies.get("auth_token")
    user = User.objects(auth_token=auth_token).first()
    if not user:
        return redirect("/signup")

    return redirect("/dashboard")


@app.route("/signup", methods=["GET"])
def signup():
    return render_template("signup.html")


@app.route("/signup", methods=["POST"])
def process_signup():
    # Collect POST request params from signup
    email = request.form["email"]
    username = request.form["username"]
    zip_code = request.form["zip"]

    # Check if email or username is already in use.
    if User.objects(email=email).first() or User.objects(username=username).first():
        return render_template(
            "signup.html",
            error="Email or username already in use.",
        )

    # Hash password (hashing means that it is encrypted and impossible to decrypt)
    # We can now only check to see if a plain text input matches the hashed password (bcrypt.checkpw).
    hashed_password = bcrypt.hashpw(bytes(str(request.form["pass"]).encode("utf-8")), bcrypt.gensalt()).decode("utf-8")

    auth_token = secrets.token_hex()

    # Create user.
    User(
        email=email,
        username=username,
        zip_code=zip_code,
        password=hashed_password,
        auth_token=auth_token,
        created=datetime.now()
    ).save()

    # Set auth cookie token
    response = redirect("/", 302)

    # Create an auth browser cookie (random letters and numbers) as our authentication
    # token so the user doesn't have to log in every single time.
    response.set_cookie('auth_token', auth_token, max_age=31540000)  # One year expiration (in seconds)

    return response


@app.route("/login", methods=["GET"])
def login():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def process_login():
    username = request.form.get("username")
    plain_pw = request.form.get("password")

    user = User.objects(username=username).first()
    if not user:
        return render_template("login.html", error="Username not found")

    correct_password = bcrypt.checkpw(bytes(plain_pw, "utf8"), bytes(user.password, "utf8"))
    if not correct_password:
        return render_template("login.html", error="incorrect password")

    response = make_response(render_template("home.html", user=user))
    response.set_cookie("auth_token", secrets.token_hex())

    return response


@app.route("/dashboard", methods=["GET"])
def dashboard():
    auth_token = request.cookies.get("auth_token")
    user = User.objects(auth_token=auth_token).first()
    if not user:
        return redirect("/signup")

    posts = [
        Post(
            date="11-17-23",
            organization="Hispanic Center Lehigh Valley",
            location="520 E Fourth St, Bethlehem, PA 18015",
            date_posted="11-12-23",
            service_type="Volunteer/Community Service",
            description="Help us out!"

        ),
        Post(
            date="11-14-23",
            organization="Community Action Lehigh Valley",
            location="514 Third Ave, Bethlehem, PA 18018",
            date_posted="11-12-23",
            service_type="Volunteer/Community Service",
            description="Help us out!"
        ),
        Post(
            date="11-12-23",
            organization="Peeps",
            location="1300 Stefko Blvd., Bethlehem, PA",
            date_posted="11-12-23",
            service_type="Internship",
            description="Don't come here."
        ),
        Post(
            date="11-14-23",
            organization="Single Mom",
            location="570 Hillside, Bethlehem, PA",
            date_posted="11-12-23",
            service_type="Moving furniture",
            description="Don't come here."
        ),
    ]
    posts.reverse()

    return render_template(
        "dashboard.html",
        user=user,
        posts=posts
    )


@app.route("/tutoring", methods=["GET"])
def tutoring():
    return render_template("tutoring.html")


@app.route("/volunteering", methods=["GET"])
def volunteering():
    return render_template("volunteer.html")


@app.route("/job-internship", methods=["GET"])
def job_internship():
    return render_template("jobinternship.html")


if __name__ == '__main__':
    app.run(debug=True, port=5555)
