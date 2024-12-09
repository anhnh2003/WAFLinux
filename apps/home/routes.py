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
@blueprint.route('/input_status')
@login_required
def input_status():
    input_status = query_iptables('INPUT')
    #parse the output into a list of lists, where each inner list represents a row of the iptables output
    table_data = parse_iptables_output(input_status)
    return render_template('home/input_status.html', table_data=table_data)



@blueprint.route('/output_status')
@login_required
def output_status():
    output_status = query_iptables('OUTPUT')
    #parse the output into a list of lists, where each inner list represents a row of the iptables output
    table_data = parse_iptables_output(output_status)
    return render_template('home/output_status.html', table_data=table_data)

@blueprint.route('/forward_status')
@login_required
def forward_status():
    forward_status = query_iptables('FORWARD')
    #parse the output into a list of lists, where each inner list represents a row of the iptables output
    table_data = parse_iptables_output(forward_status)
    return render_template('home/forward_status.html', table_data=table_data)

sudo_password = 'Gauvoi23'
def query_iptables(chain):
    command = "echo {} | sudo -S iptables -L {}".format(sudo_password, chain)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=True)
    output = process.communicate()
    return output[0].decode('utf-8')
def parse_iptables_output(output):
    table_data = []
    for line in output.splitlines():
        if line.startswith('Chain'):
            continue  # Skip the header line
        fields = line.split()
        table_data.append(fields)
    return table_data