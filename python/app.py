#!/usr/bin/env python3

import logging
import signal
import base64
import os

from flask import Flask, jsonify, request, Response
from argparse import ArgumentParser
from libs.registry import Registry
from extensions.base.burpextensionapi import BurpExtensionApi
from libs.extensionloader import ExtensionLoader
from models.wrappedmessage import WrappedMessage


LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
logging.getLogger('werkzeug').setLevel(logging.DEBUG)

app = Flask(__name__)


@app.route('/')
def index():
    return 'Hello, World!'


@app.before_request
def authorized():
    auth = request.headers.get('Authorization')
    # this comparison is not timing safe, but ignored in this scenario
    if auth and BurpExtensionApi.AUTH_TOKEN == auth:
        return None

    LOGGER.error('Unauthorized request from burp')
    return Response('{}', status=401, mimetype='application/json')


@app.route('/getregdata', methods=['POST'])
def get_register_config():
    reg_id = request.args.get('rid')
    processor = Registry.get_by_id(reg_id)
    data = {}
    if processor is not None:
        reg_data = None
        if request.json:
            reg_data = request.json
        data = processor.get_register_config(reg_data)

    return jsonify(data)


@app.route('/intruderpayloadgenerator/hasmorepayloads', methods=['POST'])
def get_intruderpayloadgenerator_hasmorepayloads():
    reg_id = request.args.get('rid')
    ipg = Registry.get_by_id(reg_id)
    has_more_payloads = False
    if ipg is not None:
        has_more_payloads = ipg.has_more_payloads()

    return jsonify(has_more_payloads)


@app.route('/intruderpayloadgenerator/getnextpayload', methods=['POST'])
def get_intruderpayloadgenerator_getnextpayloads():
    reg_id = request.args.get('rid')
    ipg = Registry.get_by_id(reg_id)
    updates = []
    if ipg is not None:
        updates = ipg.get_next_payload_update(request.args.get('payload'))

    return jsonify([u.get_data() for u in updates])


@app.route('/intruderpayloadgenerator/reset', methods=['POST'])
def get_intruderpayloadgenerator_reset():
    reg_id = request.args.get('rid')
    ipg = Registry.get_by_id(reg_id)
    if ipg is not None:
        ipg.reset()

    return ''


@app.route('/scannerinsertionpoint/buildrequest', methods=['POST'])
def get_scanpoint_request():
    reg_id = request.args.get('rid')
    ip_processor = Registry.get_by_id(reg_id)
    updates = []
    if ip_processor is not None:
        # InsertionPointRequest
        process_payload_request = request.json
        payload = process_payload_request['payload']
        req = process_payload_request['request']
        analyzed_request = process_payload_request['analyzedRequest']
        name = process_payload_request['name']
        updates = ip_processor.build_request_update(req, analyzed_request, payload, name)

    return jsonify([u.get_data() for u in updates])


@app.route('/intruder/processpayload', methods=['POST'])
def get_processed_payload():
    reg_id = request.args.get('rid')
    payload_processor = Registry.get_by_id(reg_id)
    updates = []
    if payload_processor is not None:
        # ProcessPayloadRequest
        process_payload_request = request.json
        current_payload = base64.b64decode(process_payload_request['currentPayload'])
        original_payload = base64.b64decode(process_payload_request['originalPayload'])
        base_value = base64.b64decode(process_payload_request['baseValue'])
        updates = payload_processor.get_processed_payload_update(current_payload, original_payload, base_value)

    return jsonify([u.get_data() for u in updates])


@app.route('/msgeditor/sendable', methods=['POST'])
def get_processed_message_send():
    reg_id = request.args.get('rid')
    message_processor = Registry.get_by_id(reg_id)
    updates = []
    if message_processor is not None:
        # AnalyzedMessage
        analyzed_message = request.json
        wrapped_message = WrappedMessage(analyzed_message)
        updates = message_processor.get_sendable_content_updates(wrapped_message)

    return jsonify([u.get_data() for u in updates])


@app.route('/msgeditor/readable', methods=['POST'])
def get_processed_message_display():
    reg_id = request.args.get('rid')
    message_processor = Registry.get_by_id(reg_id)
    updates = []
    if message_processor is not None:
        # AnalyzedMessage
        analyzed_message = request.json
        wrapped_message = WrappedMessage(analyzed_message)
        updates = message_processor.get_readable_content_updates(wrapped_message)

    return jsonify([u.get_data() for u in updates])


@app.route('/httplistener/processmsg', methods=['POST'])
def httplistener_processmsg():
    reg_id = request.args.get('rid')
    http_listener = Registry.get_by_id(reg_id)
    updates = []
    if http_listener is not None:
        # AnalyzedMessage
        analyzed_message = request.json
        wrapped_message = WrappedMessage(analyzed_message)
        updates = http_listener.process_http_message(wrapped_message)

    return jsonify([u.get_data() for u in updates])


@app.route('/proxylistener/processmsg', methods=['POST'])
def proxylistener_processmsg():
    reg_id = request.args.get('rid')
    proxy_listener = Registry.get_by_id(reg_id)
    updates = []
    if proxy_listener is not None:
        # InterceptedMessage
        intercepted_message = request.json
        wrapped_message = WrappedMessage(intercepted_message)
        updates = proxy_listener.process_proxy_message(wrapped_message)

    return jsonify([u.get_data() for u in updates])


@app.route('/sessionhandlingaction/perform', methods=['POST'])
def sessionhandlingaction_perform():
    reg_id = request.args.get('rid')
    action_handler = Registry.get_by_id(reg_id)
    updates = []
    if action_handler is not None:
        # SessionHandlingActionRequest
        session_handling_action_request = request.json
        wrapped_message = WrappedMessage(session_handling_action_request)
        macros = []
        for macro in request.json.get('macroItems'):
            macros.append(WrappedMessage(macro))
        updates = action_handler.perform_action(wrapped_message, macros)

    return jsonify([u.get_data() for u in updates])


@app.route('/scannercheck/passive', methods=['POST'])
def scannercheck_passive():
    reg_id = request.args.get('rid')
    action_handler = Registry.get_by_id(reg_id)
    scan_issues = []
    if action_handler is not None:
        scanner_check_request = request.json
        wrapped_message = WrappedMessage(scanner_check_request)
        scan_issues = action_handler.get_passive_scan_issues(wrapped_message)

    return jsonify([s.get_data() for s in scan_issues])


@app.route('/scannercheck/consolidate', methods=['POST'])
def scannercheck_consolidate():
    reg_id = request.args.get('rid')
    action_handler = Registry.get_by_id(reg_id)
    # new and old issue is default
    result = 0
    if action_handler is not None:
        consolidate_request = request.json
        result = action_handler.get_consolidated_issues_result(
            consolidate_request['existingIssue'], consolidate_request['newIssue'])

    return jsonify(result)


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-auth', required=True,
                        help='Authorization token, as generated by the burp extension (displayed in burp)')
    parser.add_argument('-extensions', nargs='+', required=True, help='Extensions (python files) to load')
    parser.add_argument('-localport', required=False, type=int, default=9000, help='Port to listen on')
    parser.add_argument('-targetport', required=False, type=int, default=8099,
                        help='Port the burp extension is listening on')
    args = parser.parse_args()

    # set config
    BurpExtensionApi.AUTH_TOKEN = args.auth
    BurpExtensionApi.LOCAL_PORT = args.localport
    BurpExtensionApi.TARGET_PORT = args.targetport
    BurpExtensionApi.CALLBACK_URL_BASE = BurpExtensionApi.CALLBACK_URL_BASE.format(args.localport)

    # save old handler
    if ExtensionLoader.old_handler is None:
        ExtensionLoader.old_handler = signal.getsignal(signal.SIGINT)
    # register our handler
    signal.signal(signal.SIGINT, ExtensionLoader.unregister_all)

    # debug mode, prevent double execution
    if 'true' == os.environ.get('WERKZEUG_RUN_MAIN'):
        # load the extensions within another thread to make sure the flask app is running and handling requests
        loader = ExtensionLoader()
        loader.ext_args = args.extensions
        loader.start()

    app.run(port=BurpExtensionApi.LOCAL_PORT, debug=True)
