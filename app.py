from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid 
from werkzeug.security import  generate_password_hash, check_password_hash                        
import jwt
import datetime
from functools import wraps
from flask_migrate import Migrate


# uuid - to generate a random public_id
app = Flask(__name__)

app.config["SECRETE_KEY"] = "hehaslargebrain"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///todo.db"
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


    def __repr__(self):
        return f'User("""\
        "{self.public_key}", "{self.name}", "{self.password}", "{self.admin}"\
        """)'

app.app_context().push()

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)


    def __repr__(self):
        return f'User("""\
        "{self.public_id}", "{self.name}", "{self.password}", "{self.admin}"\
        """)'
app.app_context().push()


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]
        
        if not token:
            return jsonify({"message": "token is missing"}), 401
        
        try:
            data = jwt.decode(jwt=token, key=app.config["SECRETE_KEY"],algorithms=["HS256"])
            current_user = User.query.filter_by(public_id=data["public_id"]).first()
        except Exception as ex:
            print("ERROR", ex)
            return jsonify({"message": "Token is invalid"}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated
    



# to handle the route for the user(it will be only accessable by the admin user)
# and it is basically used to see other user that are existing on the database, to create a new user and to delete user if you want to
@app.route("/user", methods=["GET"])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({"message": "cannot perform that function"}), 401
    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data["public_id"] = user.public_id
        user_data["name"] = user.name
        user_data["password"] = user.password
        user_data["admin"] = user.admin
        output.append(user_data)
    return jsonify({"user": output}), 200

@app.route("/user/<public_id>", methods=["GET"])
@token_required
def get_one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({"message": "cannot perform that function"})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"mesage": "no user found"})
    
    user_data = {}
    user_data["public_id"] = user.public_id
    user_data["name"] = user.name
    user_data["password"] = user.password
    user_data["admin"] = user.admin    
    return jsonify({"user": user_data})


@app.route("/user", methods=["POST"])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({"message": "cannot perform that function"})
    data = request.get_json()
    hashed_password = generate_password_hash(data["password"], method="pbkdf2:sha256")
    new_user = User(public_id=str(uuid.uuid4()), name=data["name"], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "new user created"})

# to promote any user_id that is pass in into an admin user
@app.route("/user/<public_id>", methods=["PUT"])
@token_required
def promote_user(current_user, public_id):
    if not current_user:
        return jsonify({"message": "cannot perform that function"})
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({"mesage": "no user found"})
    user.admin=True
    db.session.commit()

    return jsonify({"message": " The user has been promoted"})


@app.route("/user/<public_id>", methods=["DELETE"])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({"message": "cannot perform that function"})
    user = User.query.filter_by(public_id=public_id).first()
    
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "The user as been deleted"})

# working on the authentication
@app.route("/login")
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response("could not verify", 401, {"WWW-Authenticate": "basic realm='login required'"})
    user = User.query.filter_by(name=auth.username).first()
    
    if not user:
        return make_response("could not verify", 401, {"WWW-Authenticate": "Basic realm='login required'"})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({"public_id": user.public_id, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config["SECRETE_KEY"])
        
        return jsonify({"token":token})
    
    return make_response("could not verify", 401, {"WWW-Authenticate": "Basic realm='login required'"})
    
@app.route("/todo", methods=["GET"])
@token_required
def get_all_todo(current_user):
    todos = Todo.query.filter_by(user_id=current_user.id).all()
    output = []
    for todo in todos:
        todo_data = {}
        todo_data["id"] = todo.id
        todo_data["text"] = todo.text
        todo_data["complete"] = todo.complete
        todo_data["user_id"] = todo.user_id
        output.append(todo_data)
    return jsonify({"todos": output})

@app.route("/todo/<todo_id>", methods=["GET"])
@token_required
def get_one_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()
    if not todo:
        return jsonify({"message": "no todo found!"})
    
    todo_data = {}
    todo_data["id"] = todo.id
    todo_data["text"] = todo.text
    todo_data["complete"] = todo.complete
    todo_data["user_id"] = todo.user_id
    return jsonify({"todo":todo_data})

@app.route("/todo", methods=["POST"])
@token_required
def create_todo(current_user):
    data = request.get_json()
    new_todo = Todo(text=data["text"], complete=False, user_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()
    return jsonify({"message": "Todo created"})

@app.route("/todo/<todo_id>", methods=["PUT"])
@token_required
def update_a_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()
    if not todo:
        return jsonify({"mesage": "no todo found"})
    todo.complete=True
    db.session.commit()
    return jsonify({"message": "Todo item has been completed!"})

@app.route("/todo/<todo_id>", methods=["DELETE"])
@token_required
def delete_a_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()
    if not todo:
        return jsonify({"mesage": "no todo found"})
    db.session.delete(todo)
    db.session.commit()
    return jsonify({"message": "Todo item deleted!"})

if __name__ == "__main__":
    app.run(debug=True)
