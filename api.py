#!/usr/bin/env python
# This file is part of Viper - https://github.com/botherder/viper
# See the file 'LICENSE' for copying permission.

import os
import json
import copy
import argparse
import tempfile
import time
import bottle

from bottle import route, request, response, run
from bottle import HTTPError

from viper.common.objects import File
from viper.core.storage import store_sample, get_sample_path
from viper.core.database import Database
from viper.core.session import __sessions__
from viper.core.plugins import __modules__
from viper.core.project import __project__
from viper.core.ui.commands import Commands

app = application = bottle.Bottle()

db = Database()

def jsonize(data):
    return json.dumps(data, sort_keys=False, indent=4)

@app.route('/test', method='GET')
def test():
    return jsonize({'message' : 'test'})

@app.route('/file/add', method='POST')
def add_file():
    tags = request.forms.get('tags')
    upload = request.files.get('file')

    tf = tempfile.NamedTemporaryFile()
    tf.write(upload.file.read())
    tf.flush()
    tf_obj = File(tf.name)
    tf_obj.name = upload.filename

    new_path = store_sample(tf_obj)

    success = False
    if new_path:
        # Add file to the database.
        success = db.add(obj=tf_obj, tags=tags)

    if success:
        return jsonize({'message' : 'added'})
    else:
        response.status = 500
        return jsonize({'message':'Unable to store file'})

@app.route('/file/get/<file_hash>', method='GET')
def get_file(file_hash):
    key = ''
    if len(file_hash) == 32:
        key = 'md5'
    elif len(file_hash) == 64:
        key = 'sha256'
    else:
        response.code = 400
        return jsonize({'message':'Invalid hash format (use md5 or sha256)'})

    db = Database()
    rows = db.find(key=key, value=file_hash)

    if not rows:
        response.code = 404
        return jsonize({'message':'File not found in the database'})

    path = get_sample_path(rows[0].sha256)
    if not path:
        response.code = 404
        return jsonize({'message':'File not found in the repository'})

    response.content_length = os.path.getsize(path)
    response.content_type = 'application/octet-stream; charset=UTF-8'
    data = ''
    for chunk in File(path).get_chunks():
        data += chunk

    return data

@app.route('/file/delete/<file_hash>', method='GET')
def delete_file(file_hash):
    success = False
    key = ''
    if len(file_hash) == 32:
        key = 'md5'
    elif len(file_hash) == 64:
        key = 'sha256'
    else:
        response.code = 400
        return jsonize({'message':'Invalid hash format (use md5 or sha256)'})

    db = Database()
    rows = db.find(key=key, value=file_hash)

    if not rows:
        response.code = 404
        return jsonize({'message':'File not found in the database'})

    if rows:
        malware_id = rows[0].id
        path = get_sample_path(rows[0].sha256)
        if db.delete(malware_id):
            success = True
        else:
            response.code = 404
            return jsonize({'message':'File not found in repository'})

    path = get_sample_path(rows[0].sha256)
    if not path:
        response.code = 404
        return jsonize({'message':'File not found in file system'})
    else:
        success=os.remove(path)

    if success:
        return jsonize({'message' : 'deleted'})
    else:
        response.code = 500
        return jsonize({'message':'Unable to delete file'})

@app.route('/file/find', method='POST')
def find_file():
    def details(row):
        tags = []
        for tag in row.tag:
            tags.append(tag.tag)

        entry = dict(
            id=row.id,
            name=row.name,
            type=row.type,
            size=row.size,
            md5=row.md5,
            sha1=row.sha1,
            sha256=row.sha256,
            sha512=row.sha512,
            crc32=row.crc32,
            ssdeep=row.ssdeep,
            created_at=row.created_at.__str__(),
            tags=tags
        )

        return entry

    for entry in ['md5', 'sha256', 'ssdeep', 'tag', 'name', 'all','latest']:
        value = request.forms.get(entry)
        if value:
            key = entry
            break

    if not value:
        response.code = 400
        return jsonize({'message':'Invalid search term'})

    # Get the scope of the search

    project_search = request.forms.get('project')
    projects = []
    results = {}
    if project_search and project_search == 'all':
        # Get list of project paths
        projects_path = os.path.join(os.getcwd(), 'projects')
        if os.path.exists(projects_path):
            for name in os.listdir(projects_path):
                projects.append(name)
        projects.append('../')
    # Specific Project
    elif project_search:
        projects.append(project_search)
    # Primary
    else:
        projects.append('../')

    # Search each Project in the list
    for project in projects:
        __project__.open(project)
        # Init DB
        db = Database()
        #get results
        proj_results = []
        rows = db.find(key=key, value=value)
        for row in rows:
            if project == '../':
                project = 'default'
            proj_results.append(details(row))
        results[project] = proj_results
    return jsonize(results)

@app.route('/tags/list', method='GET')
def list_tags():
    rows = db.list_tags()

    results = []
    for row in rows:
        results.append(row.tag)

    return jsonize(results)

@app.route('/file/tags/add', method='POST')
def add_tags():
    tags = request.forms.get('tags')
    for entry in ['md5', 'sha256', 'ssdeep', 'tag', 'name', 'all','latest']:
        value = request.forms.get(entry)
        if value:
            key = entry
            break
    db = Database()
    rows = db.find(key=key, value=value)

    if not rows:
        response.code = 404
        return jsonize({'message':'File not found in the database'})

    for row in rows:
        malware_sha256=row.sha256
        db.add_tags(malware_sha256, tags)

    return jsonize({'message' : 'added'})

@app.route('/modules/run', method='POST')
def run_module():
    # Optional Project
    project = request.forms.get('project')
    # Optional sha256
    sha256 = request.forms.get('sha256')
    # Not Optional Command Line Args
    cmd_line = request.forms.get('cmdline')
    if project:
        __project__.open(project)
    else:
        __project__.open('../')
    if sha256:
        file_path = get_sample_path(sha256)
        if file_path:
            __sessions__.new(file_path)
    if not cmd_line:
        response.code = 404
        return jsonize({'message':'Invalid command line'})
    results = module_cmdline(cmd_line, sha256)
    __sessions__.close()
    return jsonize(results)


# this will allow complex command line parameters to be passed in via the web gui
def module_cmdline(cmd_line, sha256):
    json_data = ''
    cmd = Commands()
    split_commands = cmd_line.split(';')
    for split_command in split_commands:
        split_command = split_command.strip()
        if not split_command:
            continue
        root = ''
        args = []
        # Split words by white space.
        words = split_command.split()
        # First word is the root command.
        root = words[0]
        # If there are more words, populate the arguments list.
        if len(words) > 1:
            args = words[1:]
        try:
            if root in cmd.commands:
                cmd.commands[root]['obj'](*args)
                if cmd.output:
                    json_data += str(cmd.output)
                del(cmd.output[:])
            elif root in __modules__:
                # if prev commands did not open a session open one on the current file
                if sha256:
                    path = get_sample_path(sha256)
                    __sessions__.new(path)
                module = __modules__[root]['obj']()
                module.set_commandline(args)
                module.run()

                json_data += str(module.output)
                del(module.output[:])
            else:
                json_data += "{'message':'{0} is not a valid command'.format(cmd_line)}"
        except:
            json_data += "{'message':'Unable to complete the command: {0}'.format(cmd_line)}"
    __sessions__.close()
    return json_data

@app.route('/projects/list', method='GET')
def list_projects():
    projects_path = os.path.join(os.getcwd(), 'projects')
    if not os.path.exists(projects_path):
        response.code = 404
        return jsonize({'message':'No projects found'})
    rows = []
    for project in os.listdir(projects_path):
        project_path = os.path.join(projects_path, project)
        rows.append([project, time.ctime(os.path.getctime(project_path))])
    return jsonize(rows)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-H', '--host', help='Host to bind the API server on', default='localhost', action='store', required=False)
    parser.add_argument('-p', '--port', help='Port to bind the API server on', default=8080, action='store', required=False)
    args = parser.parse_args()

    app.run(host=args.host, port=args.port)