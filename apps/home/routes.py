# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from apps.home import blueprint
from flask import render_template, request
from flask_login import login_required
from jinja2 import TemplateNotFound
import subprocess

@blueprint.route('/')
@login_required
def default():
    return render_template('home/index.html', segment='index')
@blueprint.route('/<template>')
@login_required
def route_template(template):

    try:

        if not template.endswith('.html'):
            template += '.html'

        # Detect the current page
        segment = get_segment(request)

        # Serve the file (if exists) from app/templates/home/FILE.html
        return render_template("home/" + template, segment=segment)

    except TemplateNotFound:
        return render_template('home/page-404.html'), 404

    except:
        return render_template('home/page-500.html'), 500

# Helper - Extract current page name from request
def get_segment(request):

    try:

        segment = request.path.split('/')[-1]

        if segment == '':
            segment = 'index'

        return segment

    except:
        return None
@blueprint.route('/input')
@login_required
def input():
    input_status = query_iptables('INPUT')
    return render_template('home/input.html', status=input_status)

@blueprint.route('/output')
@login_required
def output():
    output_status = query_iptables('OUTPUT')
    return render_template('home/output.html', status=output_status)

@blueprint.route('/forward')
@login_required
def forward():
    forward_status = query_iptables('FORWARD')
    return render_template('home/forward.html', status=forward_status)

def query_iptables(chain):
    try:
        result = subprocess.run(['sudo', 'iptables', '-L', chain], capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"An error occurred while querying data: {e}"