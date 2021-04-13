"""
Copyright (c) 2020 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""
from flask import Blueprint, flash, g, redirect, render_template, request, Response, session, url_for
from werkzeug.exceptions import abort
from werkzeug.security import check_password_hash
from src.auth import login_required
from src.db import get_db
from src.iseAPI import *
from datetime import datetime
import json
import os
import urllib3


urllib3.disable_warnings()
bp = Blueprint('portal', __name__)

# TODO: BEFORE PUBLISHING THIS MUST BE SANITIZED
PXGRID_ANC_SERVICE_NAME = 'com.cisco.ise.config.anc'
DEFAULT_PXGRID_CONFIG = {
	'hostname': '',
    'nodename': '',
    'password': '',
    'description': '',
    'clientcert': 'src/certs/CLIENTCERT.cer',
    'clientkey': 'src/certs/CLIENTKEY.key',
    'clientkeypassword': '',
    'servercert': 'src/certs/SERVERCERT.cer',
    'secret': ''
}


@bp.route('/', methods=('GET', 'POST'))
@login_required
def home():
    """
    Home Page back-end functionality
    :return:
    """
    error = None
    db = get_db()
    if 'config' not in session:
        session['config'] = DEFAULT_PXGRID_CONFIG
        pxgrid_And_Endpoints = []
        error = "Warning using default config for ISE! Should be updated in Settings!"
        flash(error)
    else:
        if 'pxgrid_Account_Status' not in session:
            session['pxgrid_Account_Status'] = pxgrid_account_activate(session['config'])
        if 'iseNodeName' not in session:
            pxgrid_Services_Full = pxgrid_service_lookup(session['config'], PXGRID_ANC_SERVICE_NAME)
            session['iseNodeName'] = pxgrid_Services_Full['services'][0]['nodeName']
            session['iseNodeProperties'] = pxgrid_Services_Full['services'][0]['properties']
        if session['config']['secret'] == '':
            secret_Response = pxgrid_access_secret(session['config'], session['iseNodeName'])
            session['config']['secret'] = secret_Response['secret']

        pxgrid_And_Endpoints_Response = pxgrid_anc_endpoints(session['config'])
        pxgrid_And_Endpoints = pxgrid_And_Endpoints_Response['endpoints']

    if request.method == 'POST':
        if request.form.get('endpointToClear'):
            pxgrid_anc_clear_policy_from_Endpoint(session['config'], request.form.get('endpointToClear'))
            now = datetime.now()
            timestamp = now.strftime("%m/%d/%Y, %H:%M:%S")
            description = "Clearing ANC Policy from the endpoint {}".format(request.form.get('endpointToClear'))
            db.execute(
                'INSERT INTO tasklog (ts, type, description) VALUES (?, ?, ?)',
                (timestamp, "CLEAR", description)
            )
            db.commit()
    if error is not None:
        flash(error)
    return render_template('portal/home.html', pxgrid_Account_Status=session['pxgrid_Account_Status'], pxgrid_And_Endpoints=pxgrid_And_Endpoints)


@bp.route('/customTask', methods=('GET', 'POST'))
@login_required
def customTask():
    """
    Custom Remediation Action back-end functionality
    :return:
    """
    # PAGE SETUP
    db = get_db()
    if 'config' not in session:
        flash('Error: Issue with Configuration!')
        return redirect(url_for('portal.home'))
    if 'pxgrid_Account_Status' not in session:
        flash('Error: ISE Account not properlt enabled')
        return redirect(url_for('portal.home'))
    if 'iseNodeName' not in session:
        flash('Error: ISsE Node Name not found.')
        return redirect(url_for('portal.home'))
    if session['config']['secret'] == '':
        flash('Error: PxGrid Session Secret not found.')
        return redirect(url_for('portal.home'))

    ise_Anc_Policies = pxgrid_anc_policies(session['config'])

    service_lookup_response = pxgrid_service_lookup(session['config'], 'com.cisco.ise.session')
    service = service_lookup_response['services'][0]
    node_name = service['nodeName']
    secret_Response = pxgrid_access_secret(session['config'], node_name)
    session['config']['sessionSecret'] = secret_Response['secret']
    pxGrid_Sessions = pxgrid_Get_Sessions(session['config'])

    session['iseActiveSessions'] = pxGrid_Sessions['sessions']

    # USER INTERACTIONS
    if request.method == 'POST':
        if request.form.get('ise_endpoint') is not None and request.form.get('ise_policy') is not None:
            print('Taking Action: {} --> {}'.format(request.form.get('ise_endpoint'), request.form.get('ise_policy')))
            pxgrid_anc_apply_policy_to_Ip(session['config'], request.form.get('ise_endpoint'), request.form.get('ise_policy'))
            now = datetime.now()
            timestamp = now.strftime("%m/%d/%Y, %H:%M:%S")
            description = "Applying {} to the endpoint {}".format(request.form.get('ise_policy'), request.form.get('ise_endpoint'))
            db.execute(
                'INSERT INTO tasklog (ts, type, description) VALUES (?, ?, ?)',
                (timestamp, "CLEAR", description)
            )
            db.commit()
    return render_template('portal/customTask.html', ise_Active_Sessions=session['iseActiveSessions'], ise_Anc_Policies=ise_Anc_Policies['policies'])


@bp.route('/taskLog', methods=('GET', 'POST'))
@login_required
def taskLog():
    """
    Back-End functionality to display the application task log.
    :return:
    """
    # PAGE SETUP
    error = None
    db = get_db()
    # Retrieve Page Data Set
    task_log = db.execute(
        'SELECT t.id, ts, type, description'
        ' FROM tasklog t'
        ' ORDER BY ts DESC'
    ).fetchall()
    return render_template('portal/taskLog.html', task_log=task_log)


@bp.route('/settings', methods=('GET', 'POST'))
@login_required
def settings():
    """
    Settings Page back-end functionality
    :return:
    """
    error = None
    cert_Dir = 'src/certs'
    # Retrieve User Inputs
    if request.method == 'POST':
        # Text Areas
        if request.form.get('iseHost') != "":
            session['config']['hostname'] = request.form.get('iseHost')
        if request.form.get('iseNode') != "":
            session['config']['nodename'] = request.form.get('iseHost')
        if request.form.get('iseCertPass') != "":
            session['config']['clientkeypassword'] = request.form.get('iseHost')

        # Retrieve any uploaded files
        clientCert = request.files['clientCert']
        clientKey = request.files['clientKey']
        serverCert = request.files['serverCert']

        servicesRootCert = request.files['rootCert']
        servicesNodeCert = request.files['serviceCert']
        servicesEndpointCert = request.files['endpointCert']

        if clientCert.filename != '' and clientCert.filename.endswith('.cer'):
            clientCert.save(os.path.join(cert_Dir, clientCert.filename))
            session['config']['clientCert'] = clientCert

        if clientKey.filename != '' and clientKey.filename.endswith('.key'):
            clientKey.save(os.path.join(cert_Dir, clientKey.filename))
            session['config']['clientKey'] = clientKey

        if serverCert.filename != '' and serverCert.filename.endswith('.cer'):
            serverCert.save(os.path.join(cert_Dir, serverCert.filename))
            session['config']['serverCert'] = serverCert

        if servicesRootCert.filename != '' and servicesRootCert.filename.endswith('.cer'):
            servicesRootCert.save(os.path.join(cert_Dir, servicesRootCert.filename))
            session['config']['rootCert'] = servicesRootCert

        if servicesNodeCert.filename != '' and servicesNodeCert.filename.endswith('.cer'):
            servicesNodeCert.save(os.path.join(cert_Dir, servicesNodeCert.filename))
            session['config']['serviceCert'] = servicesNodeCert

        if servicesEndpointCert.filename != '' and servicesEndpointCert.filename.endswith('.cer'):
            servicesEndpointCert.save(os.path.join(cert_Dir, servicesEndpointCert.filename))
            session['config']['endpointCert'] = servicesEndpointCert

    return render_template('portal/settings.html', session=session)


# WEBHOOK
@bp.route('/secureXWorkflow', methods=['POST'])
def execute_SecureX_Workflow():
    """
    Back-End functionality for the SecureX WebHook.
    NOTE: This WebHook currently only supports Applying policy to Endpoints.
    To clear policy via SecureX, an additional function (similar to this) will need to be created.
    :return:
    """
    print('Request received! Authenticating...')
    if request.authorization["username"] is None or request.authorization["password"] is None:
        # Application requires user to be logged in
        return Response(status=401)
    else:
        activeUser = get_db().execute(
            'SELECT * FROM user WHERE username = ?', (request.authorization["username"],)
        ).fetchone()

        if activeUser is None:
            error = 'Username/Password not found!'
            return Response(status=401)
        elif not check_password_hash(activeUser['password'], request.authorization["password"]):
            error = 'Incorrect password.'
            return Response(status=401)
        print('Received SecureX Workflow Correctly Authenticated!')
        print('Taking Action...')
        print('--------------------------')
        payload = request.get_json()
        db = get_db()
        # If valid request format
        if "policyName" in payload and "ipAddress" in payload:
            requestSession = {}
            # Establish needed ISE connections
            requestSession['config'] = DEFAULT_PXGRID_CONFIG
            requestSession['pxgrid_Account_Status'] = pxgrid_account_activate(requestSession['config'])
            pxgrid_Services_Full = pxgrid_service_lookup(requestSession['config'], PXGRID_ANC_SERVICE_NAME)
            requestSession['iseNodeName'] = pxgrid_Services_Full['services'][0]['nodeName']
            requestSession['iseNodeProperties'] = pxgrid_Services_Full['services'][0]['properties']
            if requestSession['config']['secret'] == '':
                secret_Response = pxgrid_access_secret(requestSession['config'], requestSession['iseNodeName'])
                requestSession['config']['secret'] = secret_Response['secret']
            # Apply the policy
            pxgrid_anc_apply_policy_to_Ip(requestSession['config'], payload['ipAddress'], payload['policyName'])
            # Log action in task log
            now = datetime.now()
            timestamp = now.strftime("%m/%d/%Y, %H:%M:%S")
            description = "Applying {} to the endpoint {}".format(payload['policyName'], payload['ipAddress'])
            db.execute(
                'INSERT INTO tasklog (ts, type, description) VALUES (?, ?, ?)',
                (timestamp, "APPLY", description)
            )
            db.commit()
            return Response(status=200)
        else:
            # Unprocessable
            print('Invalid payload received.')
            return Response(status=422)
