#!/usr/bin/env python

import json
import math
import argparse
import random
import string
import logging
import time
import sys
import pika
import requests
import urllib3
import subprocess
from requests.adapters import HTTPAdapter
import multiprocessing as mp

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

base_url = 'https://localhost'

s = requests.Session()
s.mount('https://localhost/', HTTPAdapter(pool_connections=10))

admin_apikey = open('docker/.env', 'r').readline()[:-1].split("=")[1]

output = mp.Queue()

colour = {}

colour['HEADER'] = '\033[95m'
colour['BLUE'] = '\033[94m'
colour['GREEN'] = '\033[92m'
colour['WARNING'] = '\033[93m'
colour['FAIL'] = '\033[91m'
colour['ENDC'] = '\033[0m'
colour['BOLD'] = '\033[1m'
colour['UNDERLINE'] = '\033[4m'
colour[''] = ''

pool = {}

def cleanup():

    cmd = \
        """ docker exec postgres psql -U postgres -c "delete from follow where status = 'pending';" """

    try:
        subprocess.check_output(cmd, shell=True)
    except Exception, e:
        print 'failed to cleanup'
        sys.exit(1)


def gen_owner():

    owner_id = gen_rand(8)

    r = register_owner(admin_apikey, owner_id)

    apikey = r.json()['apikey']

    return (owner_id, apikey)


def log(message, clr, modifier=''):

    if clr:
        logger.info(colour[clr] + colour[modifier] + message
                    + colour['ENDC'])
    else:
        logger.info(message)


def check(response, code):

    assert_exit(response.status_code == code, 'Message = '
                + response.text + ' Status code ='
                + str(response.status_code))

def check_register(device_keys, app_keys):

    exchanges	= [".public", ".private", ".protected", ".notification", ".publish", ".diagnostics"]
    queues	= ["", ".private", ".priority", ".command", ".notification"]

    for device in device_keys:

	count = 0

	for exchange in exchanges:
    	    
    	    channel = get_channel("admin"+":"+admin_apikey)
    	    
	    log('CHECKING FOR EXISTENCE OF  ' + device+exchange + " EXCHANGE", '')
    	    
	    try:
    	        channel.exchange_declare(exchange=device+exchange, exchange_type='topic', passive=True, durable=True, auto_delete=False, internal=False, arguments=None)
    	        count = count + 1
    	    except Exception:
    	        raise
    	
    	assert(count == len(exchanges))

	count = 0
    	
	for queue in queues:
    	    
    	    channel = get_channel("admin"+":"+admin_apikey)

	    log('CHECKING FOR EXISTENCE OF  ' + device+queue + " QUEUE", '')
    	    
    	    try:
    	        channel.queue_declare(queue=device+queue, passive=True, durable=True, auto_delete=False, arguments=None)
    	        count = count + 1
    	    except Exception:
    	        raise
    	
    	assert(count == len(queues))

    for app in app_keys:
	
	count = 0

	for exchange in exchanges:
    	    
    	    channel = get_channel("admin"+":"+admin_apikey)

	    log('CHECKING FOR EXISTENCE OF  ' + app+exchange + " EXCHANGE", '')
    	    
    	    try:
    	        channel.exchange_declare(exchange=app+exchange, exchange_type='topic', passive=True, durable=True, auto_delete=False, internal=False, arguments=None)
    	        count = count + 1
    	    except Exception:
    	        raise
    	
    	assert(count == len(exchanges))

    	count = 0

    	for queue in queues:
    	    
    	    channel = get_channel("admin"+":"+admin_apikey)

	    log('CHECKING FOR EXISTENCE OF  ' + app+queue + " QUEUE", '')
    	    
    	    try:
    	        channel.queue_declare(queue=app+queue, passive=True, durable=True, auto_delete=False, arguments=None)
    	        count = count + 1
    	    except Exception:
    	        raise
    	
    	assert(count == len(queues))

def check_deregister(device_keys, app_keys):

    exchanges	= [".public", ".private", ".protected", ".notification", ".publish", ".diagnostics"]
    queues	= ["", ".private", ".priority", ".command", ".notification"]

    for device in device_keys:

	count = 0

	for exchange in exchanges:
    	    
    	    channel = get_channel("admin"+":"+admin_apikey)

	    log('CHECKING FOR NON EXISTENCE OF  ' + device+exchange+ " EXCHANGE", '')
    	    
    	    try:
    	        channel.exchange_declare(exchange=device+exchange, exchange_type='topic', passive=True, durable=True, auto_delete=False, internal=False, arguments=None)
    	    except Exception:
    	        count = count + 1
    	
    	assert(count == len(exchanges))

    	count = 0

    	for queue in queues:
    	    
    	    channel = get_channel("admin"+":"+admin_apikey)

	    log('CHECKING FOR NON EXISTENCE OF  ' + device+queue+ " QUEUE", '')
    	    
    	    try:
    	        channel.queue_declare(queue=device+queue, passive=True, durable=True, auto_delete=False, arguments=None)
    	    except Exception:
    	        count = count + 1
    	
    	assert(count == len(queues))

    for app in app_keys:

	count = 0

	for exchange in exchanges:
    	    
    	    channel = get_channel("admin"+":"+admin_apikey)

	    log('CHECKING FOR NON EXISTENCE OF  ' + app+exchange+ " EXCHANGE", '')
    	    
    	    try:
    	        channel.exchange_declare(exchange=app+exchange, exchange_type='topic', passive=True, durable=True, auto_delete=False, internal=False, arguments=None)
    	    except Exception:
    	        count = count + 1
    	
    	assert(count == len(exchanges))

    	count = 0

    	for queue in queues:
    	    
    	    channel = get_channel("admin"+":"+admin_apikey)
    	    
    	    try:
    	        channel.queue_declare(queue=app+queue, passive=True, durable=True, auto_delete=False, arguments=None)
    	    except Exception:
    	        count = count + 1
    	
    	assert(count == len(queues))
	
def assert_exit(condition, error_message):

    try:
        assert condition
    except AssertionError:

        print error_message
        raise


def gen_rand(size, prefix=''):

    rand_str = prefix + ''.join(random.choice(string.ascii_lowercase)
                                for _ in range(size))
    return rand_str


def get_entity(device_keys, app_keys, entity_type=''):

    if entity_type == 'dev':
        name = random.choice(device_keys.keys())
        key = str(device_keys[name])
    elif entity_type == 'app':
        name = random.choice(app_keys.keys())
        key = str(app_keys[name])

    return (name, key)


def get_channel(token):

    username = token.split(':')[0]
    apikey = token.split(':')[1]

    global pool

    if (token not in pool) or (pool[token].is_closed):

        credentials = pika.PlainCredentials(username, apikey)
        parameters = pika.ConnectionParameters(host='localhost',
                port=5671, credentials=credentials, ssl=True)
        connection = pika.BlockingConnection(parameters)
        channel = connection.channel()

        channel.confirm_delivery()

        pool[token] = channel

    return pool[token]


def register_owner(apikey, owner):

    url = base_url + '/admin/register-owner'
    headers = {'id': 'admin', 'apikey': apikey, 'owner': owner}
    r = s.post(url=url, headers=headers, verify=False)
    return r


def register(
    ID,
    apikey,
    entity_id,
    is_autonomous='true',
    ):

    url = base_url + '/owner/register-entity'
    headers = {
        'id': ID,
        'apikey': apikey,
        'entity': entity_id,
        'is-autonomous': is_autonomous,
        }

    r = s.post(url=url, headers=headers, data='{"test":"schema"}',
               verify=False)
    return r


def deregister(ID, apikey, entity_id):

    url = base_url + '/owner/deregister-entity'
    headers = {'id': ID, 'apikey': apikey, 'entity': entity_id}
    r = s.post(url=url, headers=headers, verify=False)
    return r


def block_unblock(
    ID,
    apikey,
    entity_id,
    req_type,
    ):

    url = base_url

    if req_type == 'block':
        url = url + '/owner/block'
    elif req_type == 'unblock':
        url = url + '/owner/unblock'

    headers = {'id': ID, 'apikey': apikey, 'entity': entity_id}
    r = s.post(url=url, headers=headers, verify=False)
    return r


def permissions(ID, apikey, entity_id=''):

    url = base_url + '/entity/permissions'

    headers = {}

    if entity_id:
        headers['entity'] = entity_id

    headers['id'] = ID
    headers['apikey'] = apikey

    r = s.get(url=url, headers=headers, verify=False)
    return r


def publish(
    ID,
    apikey,
    to,
    topic,
    message_type,
    data,
    ):

    url = base_url + '/entity/publish'
    headers = {
        'id': ID,
        'apikey': apikey,
        'to': to,
        'subject': topic,
        'message-type': message_type,
        'content-type': 'text/plain',
        }
    r = s.post(url=url, headers=headers, data=data, verify=False)
    return r


def follow(
    ID,
    apikey,
    to_id,
    permission,
    from_id='',
    topic='',
    validity='',
    message_type='',
    ):

    url = base_url + '/entity/follow'
    headers = {}

    if from_id:
        headers['from'] = from_id

    headers['id'] = ID
    headers['apikey'] = apikey
    headers['to'] = to_id

    if topic:
        headers['topic'] = topic
    else:
        headers['topic'] = 'test'

    if validity:
        headers['validity'] = validity
    else:
        headers['validity'] = '24'

    if message_type:
        headers['message-type'] = message_type

    headers['permission'] = permission

    r = s.post(url=url, headers=headers, verify=False)
    return r


def reject_follow(ID, apikey, follow_id):

    url = base_url + '/owner/reject-follow'
    headers = {'id': ID, 'apikey': apikey, 'follow-id': follow_id}
    r = s.post(url=url, headers=headers, verify=False)
    return r


def unfollow(
    ID,
    apikey,
    to,
    topic,
    permission,
    message_type,
    from_id='',
    ):

    url = base_url + '/entity/unfollow'
    headers = {}

    if from_id:
        headers['from'] = from_id

    headers['id'] = ID
    headers['apikey'] = apikey
    headers['to'] = to
    headers['topic'] = 'test'
    headers['permission'] = permission
    headers['message-type'] = message_type

    r = s.post(url=url, headers=headers, verify=False)
    return r


def share(ID, apikey, follow_id):

    url = base_url + '/owner/share'
    headers = {'id': ID, 'apikey': apikey, 'follow-id': follow_id}
    r = s.post(url=url, headers=headers, verify=False)
    return r


def bind_unbind(
    ID,
    apikey,
    to,
    topic,
    req_type,
    message_type,
    from_id='',
    is_priority='false',
    ):

    url = base_url
    headers = {}

    if req_type == 'bind':
        url = url + '/entity/bind'
    elif req_type == 'unbind':
        url = url + '/entity/unbind'

    if from_id:
        headers['from'] = from_id

    headers['message-type'] = message_type

    headers['id'] = ID
    headers['apikey'] = apikey
    headers['to'] = to
    headers['topic'] = topic
    headers['is-priority'] = is_priority

    r = s.post(url=url, headers=headers, verify=False)
    return r


def subscribe(
    ID,
    apikey,
    message_type='',
    num_messages='',
    ):

    url = base_url + '/entity/subscribe'
    headers = {}

    if message_type:
        headers['message-type'] = message_type

    if num_messages:
        headers['num-messages'] = num_messages

    headers['id'] = ID
    headers['apikey'] = apikey

    r = s.get(url=url, headers=headers, verify=False)
    return r


def follow_requests(ID, apikey, request_type):

    url = base_url

    if request_type == 'requests':
        url = url + '/owner/follow-requests'
    elif request_type == 'status':
        url = url + '/owner/follow-status'

    headers = {'id': ID, 'apikey': apikey}

    r = s.get(url=url, headers=headers, verify=False)
    return r


def dev_publish(device_keys, message_type='protected'):

    for (device, apikey) in device_keys.items():
        log('PUBLISHING MESSAGE FROM ' + device, '')
        pub_req = publish(
            device,
            apikey,
            device,
            'test',
            message_type,
            'test message from ' + device,
            )
        check(pub_req, 202)


def dev_publish_amqp(device_keys, message_type='protected'):

    for (device, apikey) in device_keys.items():
        log('PUBLISHING MESSAGE FROM ' + device, '')
        amqp_publish(device, apikey, message_type, 'test',
                     'test message from ' + device)


def non_autonomous_permissions(device_keys, app_keys):

    for (device, apikey) in device_keys.items():

        r = permissions(device, apikey)
        check(r, 403)

    for (app, apikey) in app_keys.items():

        r = permissions(app, apikey)
        check(r, 403)


def non_autonomous_reject_follow(device_keys, admin_id, admin_key):

    r = follow_requests(admin_id, admin_key, 'requests')
    response = r.json()

    for follow_request in response:

        device = str(follow_request['to']).split('.')[0]
        apikey = str(device_keys[device])
        follow_id = str(follow_request['follow-id'])

        log('NON AUTONOMOUS DEVICE ' + device
            + ' TRYING TO REJECT FOLLOW REQUESTS', '')

        r = reject_follow(device, apikey, follow_id)
        check(r, 403)


def non_autonomous_follow_status(device_keys, app_keys,
                                 req_type='status'):

    if req_type == 'requests':

        for (device, apikey) in device_keys.items():

            log('DEVICE ' + device + ' TRYING TO READ FOLLOW REQUESTS',
                '')

            r = follow_requests(device, apikey, 'requests')

            check(r, 403)

    if req_type == 'status':

        for (app, apikey) in app_keys.items():

            log('APP ' + app + ' TRYING TO READ FOLLOW STATUS', '')

            r = follow_requests(app, apikey, 'status')

            check(r, 403)


def non_autonomous_bind_unbind(
    device_keys,
    app_keys,
    req_type,
    message_type='protected',
    is_priority='false',
    ):

    for (app, apikey) in app_keys.items():

        for device in device_keys:

            log('APP ' + app + ' (UN)BINDING FROM DEVICE ' + device, '')

            bind_req = bind_unbind(
                app,
                apikey,
                device,
                'test',
                req_type,
                message_type,
                is_priority=is_priority,
                )

            check(bind_req, 403)


def bind_unbind_dev(
    device_keys,
    app_keys,
    expected=0,
    as_admin='',
    req_type='',
    message_type='protected',
    is_priority='false',
    admin_id='',
    admin_key='',
    ):

    if as_admin == False:

        approved = 0

        if message_type != 'public':

            for (app, apikey) in app_keys.items():

                log('APP ' + app
                    + ' CHECKING APPROVAL STATUS OF FOLLOW REQUESTS BEFORE BINDING'
                    , '')
                follow_status = follow_requests(app, apikey, 'status')
                response = follow_status.json()
                check(follow_status, 200)

                for entry in response:
                    if entry['status'] == 'approved':
                        approved = approved + 1

                assert_exit(approved == expected, 'Approved = '
                            + str(approved) + ' Expected = '
                            + str(expected))

                log('APP ' + app + ' HAS RECEIVED ' + str(approved)
                    + ' APPROVALS', '')
                approved = 0

        for (app, apikey) in app_keys.items():
            for device in device_keys:
                log('APP ' + app + ' (UN)BINDING FROM DEVICE '
                    + device, '')
                bind_req = bind_unbind(
                    app,
                    apikey,
                    device,
                    'test',
                    req_type,
                    message_type,
                    is_priority=is_priority,
                    )
                check(bind_req, 200)
    elif as_admin == True:

        approved = 0

        if message_type != 'public':

            for app in app_keys:

                log('APP ' + app
                    + ' CHECKING APPROVAL STATUS OF FOLLOW REQUESTS BEFORE BINDING'
                    , '')
                follow_status = follow_requests(admin_id, admin_key,
                        'status')
                response = follow_status.json()

                check(follow_status, 200)

                for entry in response:
                    if entry['status'] == 'approved':
                        approved = approved + 1

                assert_exit(approved == expected, 'Approved = '
                            + str(approved) + ' Expected = '
                            + str(expected))
                log('APP ADMIN HAS RECEIVED ' + str(approved)
                    + ' APPROVALS', '')

                approved = 0

        for app in app_keys:

            for device in device_keys:

                log('APP ' + app + ' BINDING TO DEVICE ' + device, '')

                bind_req = bind_unbind(
                    admin_id,
                    admin_key,
                    device,
                    'test',
                    req_type,
                    message_type,
                    from_id=app,
                    is_priority=is_priority,
                    )

                check(bind_req, 200)


def bind_unbind_without_follow(
    device_keys,
    app_keys,
    as_admin='',
    req_type='',
    message_type='protected',
    is_priority='false',
    admin_id='',
    admin_key='',
    ):

    if as_admin == False:
        for (app, apikey) in app_keys.items():
            for device in device_keys:
                log('APP ' + app + ' (UN)BINDING FROM DEVICE '
                    + device, '')
                bind_req = bind_unbind(
                    app,
                    apikey,
                    device,
                    'test',
                    req_type,
                    message_type,
                    is_priority=is_priority,
                    )
                check(bind_req, 403)
    elif as_admin == True:

        for app in app_keys:
            for device in device_keys:
                log('APP ' + app + ' BINDING TO DEVICE ' + device, '')
                bind_req = bind_unbind(
                    admin_id,
                    admin_key,
                    device,
                    'test',
                    req_type,
                    message_type,
                    from_id=app,
                    is_priority=is_priority,
                    )
                check(bind_req, 403)

def app_subscribe(
    devices,
    app_keys,
    expected,
    message_type='',
    ):

    count = math.ceil(devices / 100.0)

    actual = 0

    for (app, apikey) in app_keys.items():

        log('APP ' + app + ' SUBSCRIBING TO ITS QUEUE', '')

	i	= 0

        while i < count:

            if message_type:
                sub_req = subscribe(app, apikey, num_messages='100',
                                    message_type=message_type)
            else:
                sub_req = subscribe(app, apikey, num_messages='100')

            check(sub_req, 200)
            response = sub_req.json()

	    actual = actual + len(response)
	    
	    i = i + 1

        assert_exit(actual == expected, 'Actual = ' + str(actual)
                    + ' Expected = ' + str(expected))
        actual = 0
        log('APP ' + app + ' has successfully received '
            + str(expected) + ' messages', '')


def app_subscribe_amqp(
    devices,
    app_keys,
    expected,
    message_type='',
    ):

    for (app, apikey) in app_keys.items():

        log('APP ' + app + ' SUBSCRIBING TO ITS QUEUE', '')

        if message_type:
            messages = amqp_subscribe(app, apikey, devices,
                    message_type)
        else:
            messages = amqp_subscribe(app, apikey, devices,
                    message_type='')

        assert_exit(len(messages) == expected, 'Received = '
                    + str(messages) + ' Expected = ' + str(expected))

        log('APP ' + app + ' has successfully received '
            + str(expected) + ' messages', '')


def follow_dev(
    device_keys,
    app_keys,
    as_admin='',
    permission='',
    message_type='protected',
    admin_id='',
    admin_key='',
    expected=202,
    ):

    if as_admin == True:
        for app in app_keys:
            for device in device_keys:
                log('FOLLOW REQUEST FROM APP ' + app + ' TO DEVICE '
                    + device, '')
                r = follow(
                    admin_id,
                    admin_key,
                    device,
                    permission,
                    from_id=app,
                    message_type=message_type,
                    )
                check(r, expected)
    elif as_admin == False:

        for (app, apikey) in app_keys.items():
            for device in device_keys:
                log('FOLLOW REQUEST FROM APP ' + app + ' TO DEVICE '
                    + device, '')
                r = follow(app, apikey, device, permission,
                           message_type=message_type)
                check(r, expected)


def unfollow_dev(
    device_keys,
    app_keys,
    as_admin='',
    permission='',
    message_type='protected',
    admin_id='',
    admin_key='',
    expected=200,
    ):

    if as_admin == True:
        for app in app_keys:
            for device in device_keys:
                log('UNFOLLOW REQUEST FROM APP ' + app + ' TO DEVICE '
                    + device, '')
                r = unfollow(
                    admin_id,
                    admin_key,
                    device,
                    'test',
                    permission,
                    message_type,
                    from_id=app,
                    )
                check(r, expected)
    elif as_admin == False:

        for (app, apikey) in app_keys.items():
            for device in device_keys:
                log('UNFOLLOW REQUEST FROM APP ' + app + ' TO DEVICE '
                    + device, '')
                r = unfollow(
                    app,
                    apikey,
                    device,
                    'test',
                    permission,
                    message_type,
                    )
                check(r, expected)


def non_autonomous_share(device_keys, admin_id, admin_key):

    r = follow_requests(admin_id, admin_key, 'requests')
    response = r.json()

    for follow_request in response:

        device = str(follow_request['to']).split('.')[0]
        apikey = str(device_keys[device])
        follow_id = str(follow_request['follow-id'])

        log('NON AUTONOMOUS DEVICE ' + device
            + ' TRYING TO INVOKE SHARE', '')

        share_req = share(device, apikey, follow_id)
        check(share_req, 403)


def share_dev(
    device_keys,
    expected_requests,
    as_admin=False,
    admin_id='',
    admin_key='',
    expected_code=200,
    ):

    if as_admin == False:

        for (device, apikey) in device_keys.items():

            r = follow_requests(device, apikey, 'requests')
            response = r.json()
            count = 0

            check(r, 200)

            for follow_req in response:

                count = count + 1

                log('SHARE FROM DEVICE ' + device + ' TO APP '
                    + str(follow_req['from']), '')

                share_req = share(device, apikey,
                                  str(follow_req['follow-id']))

                check(share_req, expected_code)

            assert_exit(count == expected_requests, 'Actual = '
                        + str(count) + ' Expected = '
                        + str(expected_requests))
    elif as_admin == True:

        r = follow_requests(admin_id, admin_key, 'requests')
        response = r.json()
        count = 0

        check(r, 200)

        for follow_req in response:

            count = count + 1

            log('SHARE FROM DEVICE ' + str(follow_req['to']).split('.'
                )[0] + ' TO APP ' + str(follow_req['from']), '')

            share_req = share(admin_id, admin_key,
                              str(follow_req['follow-id']))

            check(share_req, expected_code)

        assert_exit(count == expected_requests, 'Actual = '
                    + str(count) + ' Expected = '
                    + str(expected_requests))


def app_publish(device_keys, app_keys, expected_code):

    for (app, apikey) in app_keys.items():
        for device in device_keys:
            log('APP ' + app + ' PUBLISHING TO DEVICE ' + device
                + '.command EXCHANGE', '')
            publish_req = publish(
                app,
                apikey,
                device,
                'test',
                'command',
                'data',
                )

            check(publish_req, expected_code)


def app_publish_amqp(device_keys, app_keys):

    for (app, apikey) in app_keys.items():
        count = 0
        for device in device_keys:
            count += 1
            log('APP ' + app + ' PUBLISHING TO DEVICE ' + device
                + '.command EXCHANGE', '')
            amqp_publish(app, apikey, 'publish', device
                         + '.command.test', 'command message from '
                         + app)


def dev_subscribe_amqp(apps, device_keys, expected):

    actual = 0

    for (device, apikey) in device_keys.items():

        log('DEVICE ' + device + ' SUBSCRIBING TO ITS COMMAND QUEUE', ''
            )

        messages = amqp_subscribe(device, apikey, expected,
                                  message_type='command')

        actual = len(messages)

        assert_exit(actual == expected, 'Actual= ' + str(actual)
                    + ' Expected = ' + str(expected))
        log('DEVICE ' + device + ' HAS RECEIVED ' + str(expected)
            + ' COMMAND MESSAGES', '')


def dev_subscribe(apps, device_keys, expected):

    count = math.ceil(apps / 100.0)

    actual = 0

    for (device, apikey) in device_keys.items():

        log('DEVICE ' + device + ' SUBSCRIBING TO ITS COMMAND QUEUE', ''
            )

	tries	= 0
	i	= 0

        while i < count + tries:

            sub_req = subscribe(device, apikey, message_type='command',
                                num_messages='100')

            check(sub_req, 200)
            response = sub_req.json()

	    actual = actual + len(response)

	    i = i + 1

        assert_exit(actual == expected, 'Actual= ' + str(actual)
                    + ' Expected = ' + str(expected))
        actual = 0
        log('DEVICE ' + device + ' HAS RECEIVED ' + str(expected)
            + ' COMMAND MESSAGES', '')


def amqp_publish(
    ID,
    apikey,
    message_type,
    routing_key,
    body,
    ):

    # credentials = pika.PlainCredentials(ID, apikey)
    # parameters = pika.ConnectionParameters(host='localhost', port=5671,
    #        credentials=credentials, ssl=True)
    # connection = pika.BlockingConnection(parameters)
    # channel = connection.channel()

    token = ID + ':' + apikey

    channel = get_channel(token)

    assert channel.basic_publish(exchange=ID + '.' + message_type,
                                 routing_key=routing_key, body=body)


def amqp_subscribe(
    ID,
    apikey,
    num_messages,
    message_type='',
    ):

    # credentials = pika.PlainCredentials(ID, apikey)
    # parameters = pika.ConnectionParameters(host='localhost', port=5671,
    #        credentials=credentials, ssl=True)
    # connection = pika.BlockingConnection(parameters)
    # channel = connection.channel()

    token = ID + ':' + apikey

    channel = get_channel(token)

    if message_type:
        message_type = '.' + message_type

    messages = []

    for (method_frame, properties, body) in channel.consume(ID
            + message_type, inactivity_timeout=1):

        if not method_frame:
            break

        channel.basic_ack(method_frame.delivery_tag)

        messages.append(body)

        if method_frame.delivery_tag == num_messages:
            break

    return messages


def registrations(
    devices,
    apps,
    dev_admin_id,
    dev_admin_key,
    app_admin_id,
    app_admin_key,
    ):

    device_keys = {}
    app_keys = {}

    # Device regsitration

    log('---------------> REGISTERING DEVICES ', 'HEADER')

    for i in range(devices):
        log('REGISTERING DEVICE ' + str(i), '')
        dev_name = 'dev' + ''.join(random.choice(string.ascii_uppercase
                                   + string.ascii_lowercase
                                   + string.digits) for _ in range(8)) \
            + str(i)

        r = register(dev_admin_id, dev_admin_key, dev_name)
        response = r.json()
        log(json.dumps(response), '')
        check(r, 201)

        device_keys[response['id']] = response['apikey']

    # App registration

    log('---------------> REGISTERING APPS', 'HEADER')

    for i in range(apps):
        log('REGISTERING APP ' + str(i), '')
        app_name = 'app' + ''.join(random.choice(string.ascii_uppercase
                                   + string.ascii_lowercase
                                   + string.digits) for _ in range(8)) \
            + str(i)

        r = register(app_admin_id, app_admin_key, app_name)
        response = r.json()
        log(json.dumps(response), '')
        check(r, 201)

        app_keys[response['id']] = response['apikey']

    return (device_keys, app_keys)


def deregistrations(
    device_keys,
    app_keys,
    dev_admin_id,
    dev_admin_key,
    app_admin_id,
    app_admin_key,
    ):

    # Deregister all apps and devices

    log('---------------> DEREGISTERING DEVICES AND APPS', 'HEADER')

    for device in device_keys:
        log('DEREGISTERING DEVICE ' + device, '')
        dereg = deregister(dev_admin_id, dev_admin_key, device)
        check(dereg, 200)

    for app in app_keys:
        log('DEREGISTERING APP ' + app, '')
        dereg = deregister(app_admin_id, app_admin_key, app)
        check(dereg, 200)


def invalid_apikey(
    devices,
    apps,
    device_keys,
    app_keys,
    dev_admin_id,
    dev_admin_key,
    app_admin_id,
    app_admin_key,
    ):

    # =========================================Invalid API key===============================================

    print '''

'''
    log('''------------------------- INVALID APIKEY -------------------------

''',
        'GREEN')

    dummy_key = gen_rand(32)
    dummy_id = gen_rand(8)

    # Owner registration ( should not go through with the right apikey anyway )

    # logger.info(colour.HEADER + "---------------> OWNER REGISTRATION USING INVALID APIKEY " + colour.ENDC)
    # r = register_owner(dummy_key, "owner"+dummy_id)
    # check(r,403)
    # logger.info("Received 403: OK")

    # Registration

    log('---------------> REGISTRATION USING INVALID APIKEY', 'HEADER')

    r = register(dev_admin_id, dummy_key, 'dev' + dummy_id)
    check(r, 403)
    log('Received 403: OK', '')

    # Publish

    log('---------------> PUBLISH USING INVALID APIKEY', 'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = publish(
        dev_name,
        dummy_key,
        dev_name,
        'test',
        'protected',
        'hello',
        )
    check(r, 403)
    log('Received 403: OK', '')

    log('---------------> PUBLISH USING VALID APIKEY TO ESTABLISH CONNECTION'
        , 'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = publish(
        dev_name,
        str(device_keys[dev_name]),
        dev_name,
        'test',
        'protected',
        'hello',
        )
    check(r, 202)
    log('Received 202: OK', '')

    log('---------------> PUBLISH USING INVALID APIKEY ONCE CONNECTION HAS BEEN ESTABLISHED'
        , 'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = publish(
        dev_name,
        dummy_key,
        dev_name,
        'test',
        'protected',
        'hello',
        )
    check(r, 403)
    log('Received 403: OK', '')

    # Subscribe

    log('---------------> SUBSCRIBE USING INVALID APIKEY', 'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = subscribe(dev_name, dummy_key)
    check(r, 403)
    log('Received 403: OK', '')

    # Follow

    log('---------------> FOLLOW USING INVALID APIKEY', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    r = follow(app_name, dummy_key, random.choice(device_keys.keys()),
               'read')
    check(r, 403)
    log('Received 403: OK', '')

    # Follow using invalid admin key

    log('---------------> FOLLOW USING INVALID ADMIN APIKEY', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')

    r = follow(app_admin_id, dummy_key,
               random.choice(device_keys.keys()), 'read')
    check(r, 403)
    log('Received 403: OK', '')

    # Share

    log('---------------> SHARE USING INVALID APIKEY', 'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = share(dev_name, dummy_key, str(random.randint(0, 5)))
    check(r, 403)
    log('Received 403: OK', '')

    # Share using invalid admin key

    log('---------------> SHARE USING INVALID ADMIN APIKEY', 'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = share(dev_admin_id, dummy_key, str(random.randint(0, 5)))
    check(r, 403)
    log('Received 403: OK', '')

    # Unfollow
    # TODO Obtain permissions before unfollowing

    log('---------------> UNFOLLOW USING INVALID APIKEY', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')

    r = unfollow(
        app_name,
        dummy_key,
        str(random.choice(device_keys.keys())),
        'test',
        'read',
        'protected',
        )
    check(r, 403)
    log('Received 403: OK', '')

    # Unfollow using invalid admin apikey

    # TODO Obtain permissions before unfollowing

    log('---------------> UNFOLLOW USING INVALID ADMIN APIKEY', 'HEADER'
        )

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')

    r = unfollow(
        app_admin_id,
        dummy_key,
        str(random.choice(device_keys.keys())),
        'test',
        'read',
        'protected',
        from_id=app_name,
        )
    check(r, 403)
    log('Received 403: OK', '')

    # Follow-requests

    log('---------------> FOLLOW-REQUESTS USING INVALID APIKEY',
        'HEADER')

    r = follow_requests(dev_admin_id, dummy_key, 'requests')
    check(r, 403)
    log('Received 403: OK', '')

    # Follow-requests using invalid device apikey

    log('---------------> FOLLOW-REQUESTS USING INVALID DEVICE APIKEY',
        'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow_requests(dev_name, dummy_key, 'requests')
    check(r, 403)
    log('Received 403: OK', '')

    # Follow-status

    log('---------------> FOLLOW-STATUS USING INVALID APIKEY', 'HEADER')

    r = follow_requests(dev_admin_id, dummy_key, 'status')
    check(r, 403)
    log('Received 403: OK', '')

    # Follow-status using invalid device apikey

    log('---------------> FOLLOW-STATUS USING INVALID DEVICE APIKEY',
        'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow_requests(dev_name, dummy_key, 'status')
    check(r, 403)
    log('Received 403: OK', '')

    # Reject follow using invalid admin key

    log('---------------> REJECT-FOLLOW USING INVALID ADMIN APIKEY',
        'HEADER')

    r = reject_follow(dev_admin_id, dummy_key, str(random.randint(1,
                      5)))
    check(r, 403)
    log('Received 403: OK', '')

    # Reject follow using invalid device key

    log('---------------> REJECT-FOLLOW USING INVALID DEVICE APIKEY',
        'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = reject_follow(dev_name, dummy_key, str(random.randint(1, 5)))
    check(r, 403)
    log('Received 403: OK', '')

    # Bind using invalid device apikey

    # TODO Obtain permissions before binding

    log('---------------> BIND USING INVALID DEVICE APIKEY', 'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')
    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')

    r = bind_unbind(
        app_name,
        dummy_key,
        dev_name,
        'test',
        'bind',
        'protected',
        )
    check(r, 403)
    log('Received 403: OK', '')

    # Bind using invalid admin apikey
    # TODO Obtain permissions before binding

    log('---------------> BIND USING INVALID ADMIN APIKEY', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = bind_unbind(
        app_admin_id,
        dummy_key,
        dev_name,
        'test',
        'bind',
        'protected',
        from_id=app_name,
        )
    check(r, 403)
    log('Received 403: OK', '')

    # Unbind using invalid device apikey
    # TODO Obtain permissions

    log('---------------> UNBIND USING INVALID DEVICE APIKEY', 'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')
    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')

    r = bind_unbind(
        app_name,
        dummy_key,
        dev_name,
        'test',
        'unbind',
        'protected',
        )
    check(r, 403)
    log('Received 403: OK', '')

    # Bind using invalid admin apikey
    # TODO Obtain permissions

    log('---------------> UNBIND USING INVALID ADMIN APIKEY', 'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')
    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')

    r = bind_unbind(
        app_admin_id,
        dummy_key,
        dev_name,
        'test',
        'unbind',
        'protected',
        from_id=app_name,
        )
    check(r, 403)
    log('Received 403: OK', '')

    # Block using invalid admin apikey

    log('---------------> BLOCK USING INVALID ADMIN APIKEY', 'HEADER')

    r = block_unblock(dev_admin_id, dummy_key,
                      str(random.choice(app_keys.keys())), 'block')
    check(r, 403)
    log('Received 403: OK', '')

    # Unblock using invalid admin apikey

    log('---------------> UNBLOCK USING INVALID ADMIN APIKEY', 'HEADER')

    r = block_unblock(dev_admin_id, dummy_key,
                      str(random.choice(app_keys.keys())), 'unblock')
    check(r, 403)
    log('Received 403: OK', '')

    # Permissions using invalid admin apikey

    log('---------------> PERMISSIONS USING INVALID ADMIN APIKEY',
        'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = permissions(dev_admin_id, dummy_key, entity_id=dev_name)
    check(r, 403)
    log('Received 403: OK', '')

    # Permissions using invalid device apikey

    log('---------------> PERMISSIONS USING INVALID DEVICE APIKEY',
        'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = permissions(dev_name, dummy_key)
    check(r, 403)
    log('Received 403: OK', '')

    # Deregister using invalid apikey

    log('---------------> DEREGISTRATION USING INVALID ADMIN APIKEY',
        'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = deregister(dev_admin_id, dummy_key, dev_name)
    check(r, 403)
    log('Received 403: OK', '')


def invalid_id(
    devices,
    apps,
    device_keys,
    app_keys,
    dev_admin_id,
    dev_admin_key,
    app_admin_id,
    app_admin_key,
    ):

    # =========================================Invalid ID===============================================

    dummy_key = gen_rand(32)
    dummy_id = gen_rand(8, prefix='admin/')
    dummy_admin_id = gen_rand(8)

    print '''

'''
    log('''------------------------- INVALID ID -------------------------

''',
        'GREEN')

    # Owner registration ( should not go through with the right apikey anyway )

    # logger.info(colour.HEADER + "---------------> OWNER REGISTRATION USING INVALID APIKEY " + colour.ENDC)
    # r = register_owner(dummy_key, "owner"+dummy_id)
    # check(r,403)
    # logger.info("Received 403: OK")

    # Registration

    log('---------------> REGISTRATION USING INVALID ID', 'HEADER')

    r = register(dummy_id, dev_admin_key, 'dev' + dummy_id)
    check(r, 403)
    log('Received 403: OK', '')

    # Publish

    log('---------------> PUBLISH USING INVALID ID', 'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = publish(
        dummy_id,
        str(device_keys[dev_name]),
        dummy_id,
        'test',
        'protected',
        'hello',
        )
    check(r, 403)
    log('Received 403: OK', '')

    log('---------------> PUBLISH USING VALID APIKEY AND ID TO ESTABLISH CONNECTION'
        , 'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = publish(
        dev_name,
        str(device_keys[dev_name]),
        dev_name,
        'test',
        'protected',
        'hello',
        )
    check(r, 202)
    log('Received 202: OK', '')

    log('---------------> PUBLISH USING INVALID ID ONCE CONNECTION HAS BEEN ESTABLISHED'
        , 'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = publish(
        dummy_id,
        str(device_keys[dev_name]),
        dummy_id,
        'test',
        'protected',
        'hello',
        )
    check(r, 403)
    log('Received 403: OK', '')

    # Subscribe

    log('---------------> SUBSCRIBE USING INVALID ID', 'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = subscribe(dummy_id, str(device_keys[dev_name]))
    check(r, 403)
    log('Received 403: OK', '')

    # Follow

    log('---------------> FOLLOW USING INVALID ID', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')

    r = follow(dummy_id, str(app_keys[app_name]),
               random.choice(device_keys.keys()), 'read')
    check(r, 403)
    log('Received 403: OK', '')

    # Follow using invalid admin id

    log('---------------> FOLLOW USING INVALID ADMIN ID', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')

    r = follow(dummy_id, app_admin_key,
               random.choice(device_keys.keys()), 'read')
    check(r, 403)
    log('Received 403: OK', '')

    # Share

    log('---------------> SHARE USING INVALID ID', 'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = share(dummy_id, str(device_keys[dev_name]),
              str(random.randint(0, 5)))
    check(r, 403)
    log('Received 403: OK', '')

    # Share using invalid admin id

    log('---------------> SHARE USING INVALID ADMIN ID', 'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = share(dummy_id, dev_admin_key, str(random.randint(0, 5)))
    check(r, 403)
    log('Received 403: OK', '')

    # Unfollow
    # TODO Obtain permissions

    log('---------------> UNFOLLOW USING INVALID ID', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')

    r = unfollow(
        dummy_id,
        str(app_keys[app_name]),
        str(random.choice(device_keys.keys())),
        'test',
        'read',
        'protected',
        )
    check(r, 403)
    log('Received 403: OK', '')

    # Unfollow using invalid admin id
    # TODO Obtain permissions

    log('---------------> UNFOLLOW USING INVALID ADMIN ID', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')

    r = unfollow(
        dummy_id,
        app_admin_key,
        str(random.choice(device_keys.keys())),
        'test',
        'read',
        'protected',
        from_id=app_name,
        )
    check(r, 403)
    log('Received 403: OK', '')

    # Follow-requests

    log('---------------> FOLLOW-REQUESTS USING INVALID ID', 'HEADER')

    r = follow_requests(dummy_id, dev_admin_key, 'requests')
    check(r, 403)
    log('Received 403: OK', '')

    # Follow-requests using invalid device id

    log('---------------> FOLLOW-REQUESTS USING INVALID DEVICE ID',
        'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow_requests(dummy_id, str(device_keys[dev_name]), 'requests'
                        )
    check(r, 403)
    log('Received 403: OK', '')

    # Follow-status

    log('---------------> FOLLOW-STATUS USING INVALID ID', 'HEADER')

    r = follow_requests(dummy_id, app_admin_key, 'status')
    check(r, 403)
    log('Received 403: OK', '')

    # Follow-status using invalid device id

    log('---------------> FOLLOW-STATUS USING INVALID DEVICE ID',
        'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow_requests(dummy_id, str(device_keys[dev_name]), 'status')
    check(r, 403)
    log('Received 403: OK', '')

    # Reject follow using invalid admin id

    log('---------------> REJECT-FOLLOW USING INVALID ADMIN ID',
        'HEADER')

    r = reject_follow(dummy_id, dev_admin_key, str(random.randint(1,
                      5)))
    check(r, 403)
    log('Received 403: OK', '')

    # Reject follow using invalid device id

    log('---------------> REJECT-FOLLOW USING INVALID DEVICE ID',
        'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = reject_follow(dummy_id, str(device_keys[dev_name]),
                      str(random.randint(1, 5)))
    check(r, 403)
    log('Received 403: OK', '')

    # Bind using invalid device id
    # TODO Obtain permissions

    log('---------------> BIND USING INVALID DEVICE ID', 'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')
    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')

    r = bind_unbind(
        dummy_id,
        str(app_keys[app_name]),
        dev_name,
        'test',
        'bind',
        'protected',
        )
    check(r, 403)
    log('Received 403: OK', '')

    # Bind using invalid admin id
    # TODO Obtain permissions

    log('---------------> BIND USING INVALID ADMIN ID', 'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')
    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')

    r = bind_unbind(
        dummy_id,
        app_admin_key,
        dev_name,
        'test',
        'bind',
        'protected',
        from_id=app_name,
        )
    check(r, 403)
    log('Received 403: OK', '')

    # Unbind using invalid device id
    # TODO Obtain permissions

    log('---------------> UNBIND USING INVALID DEVICE ID', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = bind_unbind(
        dummy_id,
        str(app_keys[app_name]),
        dev_name,
        'test',
        'unbind',
        'protected',
        )
    check(r, 403)
    log('Received 403: OK', '')

    # Bind using invalid admin id
    # TODO Obtain permissions

    log('---------------> UNBIND USING INVALID ADMIN ID', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = bind_unbind(
        dummy_id,
        app_admin_key,
        dev_name,
        'test',
        'unbind',
        'protected',
        from_id=app_name,
        )
    check(r, 403)
    log('Received 403: OK', '')

    # Block using invalid admin id

    log('---------------> BLOCK USING INVALID ADMIN ID', 'HEADER')

    r = block_unblock(dummy_admin_id, dev_admin_key,
                      str(random.choice(device_keys.keys())), 'block')
    check(r, 403)
    log('Received 403: OK', '')

    # Unblock using invalid admin id

    log('---------------> UNBLOCK USING INVALID ADMIN ID', 'HEADER')

    r = block_unblock(dummy_admin_id, dev_admin_key,
                      str(random.choice(device_keys.keys())), 'unblock')
    check(r, 403)
    log('Received 403: OK', '')

    # Permissions using invalid admin id

    log('---------------> PERMISSIONS USING INVALID ADMIN ID', 'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = permissions(dummy_admin_id, dev_admin_key, entity_id=dev_name)
    check(r, 403)
    log('Received 403: OK', '')

    # Permissions using invalid device id

    log('---------------> PERMISSIONS USING INVALID DEVICE ID', 'HEADER'
        )

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = permissions(dummy_id, str(device_keys[dev_name]))
    check(r, 403)
    log('Received 403: OK', '')

    # Deregister using invalid id

    log('---------------> DEREGISTRATION USING INVALID ADMIN ID',
        'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = deregister(dummy_id, dev_admin_key, dev_name)
    check(r, 403)
    log('Received 403: OK', '')


def invalid_publish(
    devices,
    apps,
    device_keys,
    app_keys,
    dev_admin_id,
    dev_admin_key,
    app_admin_id,
    app_admin_key,
    ):

    print '''

'''
    log('''------------------------- PUBLISH -------------------------

''',
        'GREEN')

    # Publish to non-existent exchange

    log('---------------> PUBLISH TO NON-EXISTENT EXCHANGE', 'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    dummy_exchange = gen_rand(8, prefix=gen_rand(8) + '/')
    r = publish(
        dev_name,
        dev_key,
        dummy_exchange,
        'test',
        'command',
        'hello',
        )
    check(r, 202)
    log('Received 202: OK', '')

    # Publish without authroisation

    log('---------------> PUBLISH WITHOUT AUTHORISATION', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = publish(
        app_name,
        str(app_keys[app_name]),
        dev_name,
        'test',
        'command',
        'hello',
        )
    check(r, 202)
    log('Received 202: OK', '')

    # Publish to amq.topic

    log('---------------> PUBLISH TO amq.topic', 'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = publish(
        dev_name,
        str(device_keys[dev_name]),
        'amq.topic',
        'test',
        'command',
        'hello',
        )
    check(r, 400)
    log('Received 400: OK', '')

    # Publish to amq.direct

    log('---------------> PUBLISH TO amq.direct', 'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = publish(
        dev_name,
        str(device_keys[dev_name]),
        'amq.direct',
        'test',
        'command',
        'hello',
        )
    check(r, 400)
    log('Received 400: OK', '')

    # Publish to amq.headers

    log('---------------> PUBLISH TO amq.headers', 'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = publish(
        dev_name,
        str(device_keys[dev_name]),
        'amq.headers',
        'test',
        'command',
        'hello',
        )
    check(r, 400)
    log('Received 400: OK', '')

    # Publish to amq.fanout

    log('---------------> PUBLISH TO amq.fanout', 'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = publish(
        dev_name,
        str(device_keys[dev_name]),
        'amq.fanout',
        'test',
        'command',
        'hello',
        )
    check(r, 400)
    log('Received 400: OK', '')

    # Publish with invalid message-type

    log('---------------> PUBLISH WITH INVALID MESSAGE-TYPE', 'HEADER')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = publish(
        dev_name,
        str(device_keys[dev_name]),
        dev_name,
        'test',
        gen_rand(8),
        'hello',
        )
    check(r, 400)
    log('Received 400: OK', '')


def invalid_subscribe(
    devices,
    apps,
    device_keys,
    app_keys,
    dev_admin_id,
    dev_admin_key,
    app_admin_id,
    app_admin_key,
    ):

    print '''

'''
    log('''------------------------- SUBSCRIBE -------------------------

''',
        'GREEN')

    # With invalid message type

    log('---------------> SUBSCRIBE WITH INVALID MESSAGE-TYPE', 'HEADER'
        )
    dummy_mt = gen_rand(8)

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')

    r = subscribe(app_name, app_key, dummy_mt)
    check(r, 400)
    log('Received 400: OK', '')

    # With invalid num messages

    log('---------------> SUBSCRIBE WITH INVALID NUM MESSSAGES',
        'HEADER')
    dummy_nm = gen_rand(8)

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')

    r = subscribe(app_name, app_key, num_messages=dummy_nm)
    check(r, 400)
    log('Received 400: OK ', '')


def invalid_bind(
    devices,
    apps,
    device_keys,
    app_keys,
    dev_admin_id,
    dev_admin_key,
    app_admin_id,
    app_admin_key,
    ):

    print '''

'''
    log('''------------------------- BIND -------------------------

''',
        'GREEN')

    # Bind to unauthorised exchange

    log('---------------> BIND TO UNAUTHORISED EXCHANGE', 'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')

    r = bind_unbind(
        app_name,
        str(app_keys[app_name]),
        dev_name,
        'test',
        'bind',
        'protected',
        )
    check(r, 403)
    log('Received 403: OK', '')

    # Bind to non-existent exchange

    log('---------------> BIND TO NON-EXISTENT EXCHANGE', 'HEADER')

    dummy_exchange = gen_rand(8, prefix=gen_rand(8))
    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')

    r = bind_unbind(
        app_name,
        str(app_keys[app_name]),
        dummy_exchange,
        'test',
        'bind',
        'protected',
        )
    check(r, 403)
    log('Received 403: OK', '')

    # Bind using invalid message_type

    log('---------------> BIND USING INVALID MESSAGE-TYPE', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow(app_name, str(app_keys[app_name]), dev_name, 'read')
    follow_id = r.json()['follow-id-read']
    check(r, 202)

    r = share(dev_name, str(device_keys[dev_name]), follow_id)
    check(r, 200)

    r = bind_unbind(
        app_name,
        str(app_keys[app_name]),
        dev_name,
        'test',
        'bind',
        gen_rand(8),
        )
    check(r, 400)
    log('Received 400: OK', '')

    r = unfollow(
        app_name,
        str(app_keys[app_name]),
        dev_name,
        'test',
        'read',
        'protected',
        )
    check(r, 200)

    cmd = \
        """ docker exec postgres psql -U postgres -c "delete from follow" """

    try:
        p = subprocess.check_output(cmd, shell=True)
    except Exception, e:
        pass

    # Bind with a different topic from what was requested in follow

    log('---------------> BIND USING UNAUTHORISED TOPIC', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow(app_name, str(app_keys[app_name]), dev_name, 'read')
    follow_id = r.json()['follow-id-read']
    check(r, 202)

    r = share(dev_name, str(device_keys[dev_name]), follow_id)
    check(r, 200)

    dummy_topic = gen_rand(8)
    r = bind_unbind(
        app_name,
        str(app_keys[app_name]),
        dev_name,
        dummy_topic,
        'bind',
        'protected',
        )
    check(r, 403)
    log('Received 403: OK', '')

    r = unfollow(
        app_name,
        str(app_keys[app_name]),
        dev_name,
        'test',
        'read',
        'protected',
        )
    check(r, 200)

    cmd = \
        """ docker exec postgres psql -U postgres -c "delete from follow" """

    try:
        p = subprocess.check_output(cmd, shell=True)
    except Exception, e:
        pass

    # Cross-owner binding

    log('---------------> CROSS OWNER BINDING', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow(app_name, str(app_keys[app_name]), dev_name, 'read')
    follow_id = r.json()['follow-id-read']
    check(r, 202)

    r = share(dev_name, str(device_keys[dev_name]), follow_id)
    check(r, 200)

    r = bind_unbind(
        dev_admin_id,
        dev_admin_key,
        dev_name,
        'test',
        'bind',
        'protected',
        from_id=app_name,
        )
    check(r, 403)
    log('Received 403: OK', '')

    r = unfollow(
        app_name,
        str(app_keys[app_name]),
        dev_name,
        'test',
        'read',
        'protected',
        )
    check(r, 200)

    cmd = \
        """ docker exec postgres psql -U postgres -c "delete from follow" """

    try:
        p = subprocess.check_output(cmd, shell=True)
    except Exception, e:
        pass

    # Cross-device binding

    log('---------------> CROSS DEVICE BINDING', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow(app_name, str(app_keys[app_name]), dev_name, 'read')
    follow_id = r.json()['follow-id-read']
    check(r, 202)

    r = share(dev_name, str(device_keys[dev_name]), follow_id)
    check(r, 200)

    (dummy_dev, dummy_dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = bind_unbind(
        dummy_dev,
        dummy_dev_key,
        dev_name,
        'test',
        'bind',
        'protected',
        from_id=app_name,
        )
    check(r, 403)
    log('Received 403: OK', '')

    r = unfollow(
        app_name,
        str(app_keys[app_name]),
        dev_name,
        'test',
        'read',
        'protected',
        )
    check(r, 200)

    cmd = \
        """ docker exec postgres psql -U postgres -c "delete from follow" """

    try:
        p = subprocess.check_output(cmd, shell=True)
    except Exception, e:
        pass


def invalid_unbind(
    devices,
    apps,
    device_keys,
    app_keys,
    dev_admin_id,
    dev_admin_key,
    app_admin_id,
    app_admin_key,
    ):

    print '''

'''
    log('''------------------------- UNBIND -------------------------

''',
        'GREEN')

    # Unbind to unauthorised exchange

    log('---------------> UNBIND FROM UNAUTHORISED EXCHANGE', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = bind_unbind(
        app_name,
        str(app_keys[app_name]),
        dev_name,
        'test',
        'unbind',
        'protected',
        )
    check(r, 403)
    log('Received 403: OK', '')

    # Unbind to non-existent exchange

    log('---------------> UNBIND FROM NON-EXISTENT EXCHANGE', 'HEADER')

    dummy_exchange = gen_rand(8, prefix=gen_rand(8))

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')

    r = bind_unbind(
        app_name,
        str(app_keys[app_name]),
        dummy_exchange,
        'test',
        'unbind',
        'protected',
        )
    check(r, 403)
    log('Received 403: OK', '')

    # Unbind using invalid message_type

    log('---------------> UNBIND USING INVALID MESSAGE-TYPE', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow(app_name, str(app_keys[app_name]), dev_name, 'read')
    follow_id = r.json()['follow-id-read']
    check(r, 202)

    r = share(dev_name, dev_key, follow_id)
    check(r, 200)

    r = bind_unbind(
        app_name,
        app_key,
        dev_name,
        'test',
        'bind',
        'protected',
        )
    check(r, 200)
    log('Received 200: OK', '')

    r = bind_unbind(
        app_name,
        app_key,
        dev_name,
        'test',
        'unbind',
        gen_rand(8),
        )
    check(r, 400)
    log('Received 400: OK', '')

    r = unfollow(
        app_name,
        str(app_keys[app_name]),
        dev_name,
        'test',
        'read',
        'protected',
        )
    check(r, 200)

    cmd = \
        """ docker exec postgres psql -U postgres -c "delete from follow" """

    try:
        p = subprocess.check_output(cmd, shell=True)
    except Exception, e:
        pass

    # Unbind with a different topic from what was requested in follow

    log('---------------> UNBIND USING UNAUTHORISED TOPIC', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow(app_name, str(app_keys[app_name]), dev_name, 'read')
    follow_id = r.json()['follow-id-read']
    check(r, 202)

    r = share(dev_name, str(device_keys[dev_name]), follow_id)
    check(r, 200)

    r = bind_unbind(
        app_name,
        str(app_keys[app_name]),
        dev_name,
        'test',
        'bind',
        'protected',
        )
    check(r, 200)
    log('Received 200: OK', '')

    r = bind_unbind(
        app_name,
        str(app_keys[app_name]),
        dev_name,
        gen_rand(8),
        'unbind',
        'protected',
        )
    check(r, 403)
    log('Received 403: OK', '')

    r = unfollow(
        app_name,
        str(app_keys[app_name]),
        dev_name,
        'test',
        'read',
        'protected',
        )
    check(r, 200)

    cmd = \
        """ docker exec postgres psql -U postgres -c "delete from follow" """

    try:
        p = subprocess.check_output(cmd, shell=True)
    except Exception, e:
        pass

    # Cross-owner Unbinding

    log('---------------> CROSS OWNER UNBINDING', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow(app_name, str(app_keys[app_name]), dev_name, 'read')
    follow_id = r.json()['follow-id-read']
    check(r, 202)

    r = share(dev_name, str(device_keys[dev_name]), follow_id)
    check(r, 200)

    r = bind_unbind(
        app_name,
        str(app_keys[app_name]),
        dev_name,
        'test',
        'bind',
        'protected',
        )
    check(r, 200)
    log('Received 200: OK', '')

    r = bind_unbind(
        dev_admin_id,
        dev_admin_key,
        dev_name,
        'test',
        'unbind',
        'protected',
        from_id=app_name,
        )
    check(r, 403)
    log('Received 403: OK', '')

    r = unfollow(
        app_name,
        str(app_keys[app_name]),
        dev_name,
        'test',
        'read',
        'protected',
        )
    check(r, 200)

    cmd = \
        """ docker exec postgres psql -U postgres -c "delete from follow" """

    try:
        p = subprocess.check_output(cmd, shell=True)
    except Exception, e:
        pass

    # Cross-device unbinding

    log('---------------> CROSS DEVICE UNBINDING', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow(app_name, str(app_keys[app_name]), dev_name, 'read')
    follow_id = r.json()['follow-id-read']
    check(r, 202)

    r = share(dev_name, str(device_keys[dev_name]), follow_id)
    check(r, 200)

    (dummy_dev, dummy_dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = bind_unbind(
        app_name,
        str(app_keys[app_name]),
        dev_name,
        'test',
        'bind',
        'protected',
        )
    check(r, 200)
    log('Received 200: OK', '')

    r = bind_unbind(
        dummy_dev,
        dummy_dev_key,
        dev_name,
        'test',
        'unbind',
        'protected',
        from_id=app_name,
        )
    check(r, 403)
    log('Received 403: OK', '')

    r = unfollow(
        app_name,
        str(app_keys[app_name]),
        dev_name,
        'test',
        'read',
        'protected',
        )
    check(r, 200)

    cmd = \
        """ docker exec postgres psql -U postgres -c "delete from follow" """

    try:
        p = subprocess.check_output(cmd, shell=True)
    except Exception, e:
        pass


def invalid_share(
    devices,
    apps,
    device_keys,
    app_keys,
    dev_admin_id,
    dev_admin_key,
    app_admin_id,
    app_admin_key,
    ):

    print '''

'''
    log('''------------------------- SHARE -------------------------

''',
        'GREEN')

    # Cross-device share / Share to self

    log('---------------> SHARE TO SELF USING DEVICE APIKEY', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow(app_name, app_key, dev_name, 'read')
    follow_id = r.json()['follow-id-read']
    check(r, 202)

    r = share(app_name, app_key, follow_id)
    check(r, 400)
    log('Received 400: OK', '')

    cmd = \
        """ docker exec postgres psql -U postgres -c "delete from follow" """

    try:
        p = subprocess.check_output(cmd, shell=True)
    except Exception, e:
        pass

    # Cross-owner share / Share to self using owner's key

    log('---------------> SHARE TO SELF USING OWNER APIKEY', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow(app_name, app_key, dev_name, 'read')
    follow_id = r.json()['follow-id-read']
    check(r, 202)

    r = share(app_admin_id, app_admin_key, follow_id)
    check(r, 400)
    log('Received 400: OK', '')

    cmd = \
        """ docker exec postgres psql -U postgres -c "delete from follow" """

    try:
        p = subprocess.check_output(cmd, shell=True)
    except Exception, e:
        pass

    # Share on behalf of another device

    log('---------------> SHARE BY ANOTHER DEVICE', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow(app_name, app_key, dev_name, 'read')
    follow_id = r.json()['follow-id-read']
    check(r, 202)

    dev_copy = copy.deepcopy(device_keys)
    dev_copy.pop(dev_name, None)

    dummy_dev = random.choice(dev_copy.keys())
    dummy_dev_key = str(dev_copy[dummy_dev])

    r = share(dummy_dev, dummy_dev_key, follow_id)
    check(r, 400)
    log('Received 400: OK', '')

    cmd = \
        """ docker exec postgres psql -U postgres -c "delete from follow" """

    try:
        p = subprocess.check_output(cmd, shell=True)
    except Exception, e:
        pass

    # Share using invalid follow-id

    log('---------------> SHARE USING INVALID FOLLOW-ID', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow(app_name, app_key, dev_name, 'read')
    follow_id = r.json()['follow-id-read']
    check(r, 202)

    r = share(dev_name, dev_key, gen_rand(8))
    check(r, 500)
    log('Received 500: OK', '')

    cmd = \
        """ docker exec postgres psql -U postgres -c "delete from follow" """

    try:
        p = subprocess.check_output(cmd, shell=True)
    except Exception, e:
        pass


def invalid_follow(
    devices,
    apps,
    device_keys,
    app_keys,
    dev_admin_id,
    dev_admin_key,
    app_admin_id,
    app_admin_key,
    ):

    print '''

'''
    log('''------------------------- FOLLOW -------------------------

''',
        'GREEN')

    # Invalid from

    log('---------------> FOLLOW USING INVALID FROM-ID', 'HEADER')

    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow(app_admin_id, app_admin_key, dev_name, 'read',
               from_id=gen_rand(8, prefix=gen_rand(8)))
    check(r, 403)
    log('Received 403: OK', '')

    # Invalid to-id

    log('---------------> FOLLOW USING INVALID TO-ID', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')

    r = follow(app_name, str(app_keys[app_name]), gen_rand(8,
               prefix=gen_rand(8)), 'read')
    check(r, 403)
    log('Received 403: OK', '')

    # Invalid validity period - large validity

    log('---------------> FOLLOW USING INVALID VALIDITY PERIOD - LARGE VALIDITY'
        , 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    validity = random.randint(1000000, 100000000)
    r = follow(app_name, app_key, dev_name, 'read',
               validity=str(validity))
    check(r, 400)
    log('Received 400: OK', '')

    # Invalid validity period - non numeric validity

    log('---------------> FOLLOW USING INVALID VALIDITY PERIOD - NON NUMERIC VALIDITY'
        , 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    validity = gen_rand(8)
    r = follow(app_name, app_key, dev_name, 'read', validity=validity)
    check(r, 400)
    log('Received 400: OK', '')

    cmd = \
        """ docker exec postgres psql -U postgres -c "delete from follow" """

    try:
        p = subprocess.check_output(cmd, shell=True)
    except Exception, e:
        pass

    # Cross-owner follow

    log('---------------> CROSS-OWNER FOLLOW', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow(dev_admin_id, dev_admin_key, dev_name, 'read',
               from_id=app_name)
    check(r, 403)
    log('Received 403: OK', '')

    # Cross-device follow

    log('---------------> CROSS-DEVICE FOLLOW', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow(dev_name, dev_key, dev_name, 'read', from_id=app_name)
    check(r, 202)
    log('Received 202: OK', '')

    cmd = \
        """ docker exec postgres psql -U postgres -c "delete from follow" """

    try:
        p = subprocess.check_output(cmd, shell=True)
    except Exception, e:
        pass

    # Invalid permission

    log('---------------> FOLLOW USING INVALID PERMISSION', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    permission = gen_rand(8)

    r = follow(app_name, app_key, dev_name, permission)
    check(r, 400)
    log('Received 400: OK', '')

    # Invalid message-type

    log('---------------> FOLLOW USING INVALID MESSAGE-TYPE', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow(app_name, app_key, dev_name, 'read',
               message_type=gen_rand(8))
    check(r, 400)
    log('Received 400: OK', '')


def invalid_unfollow(
    devices,
    apps,
    device_keys,
    app_keys,
    dev_admin_id,
    dev_admin_key,
    app_admin_id,
    app_admin_key,
    ):

    print '''

'''
    log('''------------------------- UNFOLLOW -------------------------

''',
        'GREEN')

    # Invalid to-id

    log('---------------> UNFOLLOW USING INVALID TO-ID', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow(app_name, app_key, dev_name, 'read')
    follow_id = r.json()['follow-id-read']
    check(r, 202)

    r = share(dev_name, dev_key, follow_id)
    check(r, 200)

    r = bind_unbind(
        app_name,
        str(app_keys[app_name]),
        dev_name,
        'test',
        'bind',
        'protected',
        )
    check(r, 200)
    log('Received 200: OK', '')

    r = unfollow(
        app_name,
        app_key,
        gen_rand(8, prefix=gen_rand(8)),
        'test',
        'read',
        'protected',
        )
    check(r, 403)
    log('Received 403: OK', '')

    r = unfollow(
        app_name,
        app_key,
        dev_name,
        'test',
        'read',
        'protected',
        )
    check(r, 200)

    cmd = \
        """ docker exec postgres psql -U postgres -c "delete from follow" """

    try:
        p = subprocess.check_output(cmd, shell=True)
    except Exception, e:
        pass

    # Invalid permission

    log('---------------> UNFOLLOW USING INVALID PERMISSION', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow(app_name, app_key, dev_name, 'read')
    follow_id = r.json()['follow-id-read']
    check(r, 202)

    r = share(dev_name, dev_key, follow_id)
    check(r, 200)

    r = bind_unbind(
        app_name,
        str(app_keys[app_name]),
        dev_name,
        'test',
        'bind',
        'protected',
        )
    check(r, 200)
    log('Received 403: OK', '')
    permission = gen_rand(8)

    r = unfollow(
        app_name,
        app_key,
        dev_name,
        'test',
        permission,
        'protected',
        )
    check(r, 400)
    log('Received 400: OK', '')

    r = unfollow(
        app_name,
        app_key,
        dev_name,
        'test',
        'read',
        'protected',
        )
    check(r, 200)

    cmd = \
        """ docker exec postgres psql -U postgres -c "delete from follow" """

    try:
        p = subprocess.check_output(cmd, shell=True)
    except Exception, e:
        pass

    # Cross-owner follow

    log('---------------> CROSS-OWNER UNFOLLOW', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow(app_name, app_key, dev_name, 'read')
    follow_id = r.json()['follow-id-read']
    check(r, 202)

    r = share(dev_name, dev_key, follow_id)
    check(r, 200)

    r = bind_unbind(
        app_name,
        str(app_keys[app_name]),
        dev_name,
        'test',
        'bind',
        'protected',
        )
    check(r, 200)
    log('Received 200: OK', '')

    r = unfollow(
        dev_admin_id,
        dev_admin_key,
        dev_name,
        'test',
        'read',
        'protected',
        from_id=app_name,
        )
    check(r, 403)
    log('Received 403: OK', '')

    r = unfollow(
        app_name,
        app_key,
        dev_name,
        'test',
        'read',
        'protected',
        )
    check(r, 200)

    cmd = \
        """ docker exec postgres psql -U postgres -c "delete from follow" """

    try:
        p = subprocess.check_output(cmd, shell=True)
    except Exception, e:
        pass

    # Cross-device follow

    log('---------------> CROSS-DEVICE UNFOLLOW', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow(app_name, app_key, dev_name, 'read')
    follow_id = r.json()['follow-id-read']
    check(r, 202)

    r = share(dev_name, dev_key, follow_id)
    check(r, 200)

    r = bind_unbind(
        app_name,
        str(app_keys[app_name]),
        dev_name,
        'test',
        'bind',
        'protected',
        )
    check(r, 200)
    log('Received 200: OK', '')

    r = unfollow(
        dev_name,
        dev_key,
        dev_name,
        'test',
        'read',
        'protected',
        from_id=app_name,
        )
    check(r, 403)
    log('Received 403: OK', '')

    r = unfollow(
        app_name,
        app_key,
        dev_name,
        'test',
        'read',
        'protected',
        )
    check(r, 200)

    cmd = \
        """ docker exec postgres psql -U postgres -c "delete from follow" """

    try:
        p = subprocess.check_output(cmd, shell=True)
    except Exception, e:
        pass

    # Invalid message-type

    log('---------------> UNFOLLOW USING INVALID MESSAGE-TYPE', 'HEADER'
        )

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow(app_name, app_key, dev_name, 'read')
    follow_id = r.json()['follow-id-read']
    check(r, 202)

    r = share(dev_name, dev_key, follow_id)
    check(r, 200)

    r = bind_unbind(
        app_name,
        str(app_keys[app_name]),
        dev_name,
        'test',
        'bind',
        'protected',
        )
    check(r, 200)
    log('Received 200: OK', '')

    r = unfollow(
        app_name,
        app_key,
        dev_name,
        'test',
        'read',
        message_type=gen_rand(8),
        )
    check(r, 403)
    log('Received 403: OK', '')

    r = unfollow(
        app_name,
        app_key,
        dev_name,
        'test',
        'read',
        'protected',
        )
    check(r, 200)

    cmd = \
        """ docker exec postgres psql -U postgres -c "delete from follow" """

    try:
        p = subprocess.check_output(cmd, shell=True)
    except Exception, e:
        pass


def invalid_deregistrations(
    devices,
    apps,
    device_keys,
    app_keys,
    dev_admin_id,
    dev_admin_key,
    app_admin_id,
    app_admin_key,
    ):

    print '''

'''
    log('''------------------------- DEREGISTRATION -------------------------

''',
        'GREEN')

    # Cross-owner deregistrations

    log('---------------> CROSS-OWNER DEREGISTRATIONS', 'HEADER')

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = deregister(dev_admin_id, dev_admin_key, app_name)
    check(r, 403)
    log('Received 403: OK', '')

    r = deregister(app_admin_id, app_admin_key, dev_name)
    check(r, 403)
    log('Received 403: OK', '')

def private_exchange_tests(
    devices,
    apps,
    device_keys,
    app_keys,
    dev_admin_id,
    dev_admin_key,
    app_admin_id,
    app_admin_key,
    ):

    print '''

'''
    log('''------------------------- PRIVATE EXCHANGE TESTS -------------------------

''',
        'GREEN')

    log('---------------> FOLLOW USING PRIVATE MESSAGE-TYPE', 'HEADER'
        )

    (app_name, app_key) = get_entity(device_keys, app_keys,
            entity_type='app')
    (dev_name, dev_key) = get_entity(device_keys, app_keys,
            entity_type='dev')

    r = follow(app_name, app_key, dev_name, 'read', message_type="private")
    check(r, 400)
    log('Received 403: OK', '')

    log('---------------> BIND USING PRIVATE MESSAGE-TYPE', 'HEADER'
        )

    r = follow(app_name, app_key, dev_name, 'read')
    follow_id = r.json()['follow-id-read']
    check(r, 202)
    log('Received 202: OK', '')

    r = share(dev_name, dev_key, follow_id)
    check(r, 200)

    r = bind_unbind(
        app_name,
        str(app_keys[app_name]),
        dev_name,
        'test',
        'bind',
        'private',
        )
    check(r, 403)
    log('Received 403: OK', '')

def is_autonomous(devices, apps):

    print '''

'''
    log('''========================= IS-AUTONOMOUS TEST CASES =========================

''',
        'GREEN', modifier='BOLD')

    device_keys = {}
    app_keys = {}

    (dev_admin_id, dev_admin_key) = gen_owner()
    (app_admin_id, app_admin_key) = gen_owner()

    log('---------------> REGISTERING DEVICES ', 'HEADER')

    for i in range(devices):
        log('REGISTERING DEVICE ' + str(i), '')
        dev_name = 'dev' + ''.join(random.choice(string.ascii_uppercase
                                   + string.ascii_lowercase
                                   + string.digits) for _ in range(8)) \
            + str(i)

        r = register(dev_admin_id, dev_admin_key, dev_name,
                     is_autonomous='false')
        response = r.json()
        log(json.dumps(response), '')
        check(r, 201)

        device_keys[response['id']] = response['apikey']

    log('---------------> REGISTERING APPS', 'HEADER')

    for i in range(apps):
        log('REGISTERING APP ' + str(i), '')
        dev_name = 'app' + ''.join(random.choice(string.ascii_uppercase
                                   + string.ascii_lowercase
                                   + string.digits) for _ in range(8)) \
            + str(i)

        r = register(app_admin_id, app_admin_key, dev_name,
                     is_autonomous='false')
        response = r.json()
        log(json.dumps(response), '')
        check(r, 201)

        app_keys[response['id']] = response['apikey']

    print '''

'''
    log('''------------------------- FOLLOW API -------------------------

''',
        'GREEN')

    log('---------------> DEVICES TRY TO FOLLOW WITH READ PERMISSION ',
        'HEADER')

    follow_dev(device_keys, app_keys, as_admin=False, permission='read'
               , expected=403)

    print '''

'''
    log('''------------------------- UNFOLLOW API -------------------------

''',
        'GREEN')

    log('---------------> FOLLOW REQUESTS AS ADMIN ', 'HEADER')

    follow_dev(
        device_keys,
        app_keys,
        as_admin=True,
        permission='read',
        admin_id=app_admin_id,
        admin_key=app_admin_key,
        )

    log('---------------> DEVICES READ FOLLOW REQUESTS AND ISSUE SHARE TO APPS'
        , 'HEADER')

    share_dev(device_keys, apps * devices, as_admin=True,
              admin_id=dev_admin_id, admin_key=dev_admin_key)

    log('---------------> APPS TRY TO UNFOLLOW DEVICES', 'HEADER')

    unfollow_dev(device_keys, app_keys, as_admin=False,
                 permission='read', expected=403)

    log('---------------> APPS UNFOLLOW DEVICES USING ADMIN APIKEY',
        'HEADER')

    unfollow_dev(
        device_keys,
        app_keys,
        as_admin=True,
        permission='read',
        admin_id=app_admin_id,
        admin_key=app_admin_key,
        )

    print '''

'''
    log('''------------------------- SHARE API -------------------------

''',
        'GREEN')

    log('---------------> FOLLOW REQUESTS AS ADMIN ', 'HEADER')

    follow_dev(
        device_keys,
        app_keys,
        as_admin=True,
        permission='read',
        admin_id=app_admin_id,
        admin_key=app_admin_key,
        )

    log('---------------> DEVICES TRY TO INVOKE SHARE ', 'HEADER')

    non_autonomous_share(device_keys, dev_admin_id, dev_admin_key)

    print '''

'''
    log('''------------------------- BIND API -------------------------

''',
        'GREEN')

    cleanup()

    log('---------------> FOLLOW REQUESTS AS ADMIN ', 'HEADER')

    follow_dev(
        device_keys,
        app_keys,
        as_admin=True,
        permission='read',
        admin_id=app_admin_id,
        admin_key=app_admin_key,
        )

    log('---------------> DEVICES READ FOLLOW REQUESTS AND ISSUE SHARE TO APPS'
        , 'HEADER')

    share_dev(device_keys, apps * devices, as_admin=True,
              admin_id=dev_admin_id, admin_key=dev_admin_key)

    log('---------------> NON AUTONOMOUS APPS TRY TO BIND ', 'HEADER')

    non_autonomous_bind_unbind(device_keys, app_keys, 'bind')

    log('---------------> APPS UNFOLLOW DEVICES USING ADMIN APIKEY',
        'HEADER')

    unfollow_dev(
        device_keys,
        app_keys,
        as_admin=True,
        permission='read',
        admin_id=app_admin_id,
        admin_key=app_admin_key,
        )

    print '''

'''
    log('''------------------------- UNBIND API -------------------------

''',
        'GREEN')

    cleanup()

    log('---------------> FOLLOW REQUESTS AS ADMIN ', 'HEADER')

    follow_dev(
        device_keys,
        app_keys,
        as_admin=True,
        permission='read',
        admin_id=app_admin_id,
        admin_key=app_admin_key,
        )

    log('---------------> DEVICES READ FOLLOW REQUESTS AND ISSUE SHARE TO APPS'
        , 'HEADER')

    share_dev(device_keys, apps * devices, as_admin=True,
              admin_id=dev_admin_id, admin_key=dev_admin_key)

    log('---------------> APPS BIND TO DEVICES USING ADMIN APIKEY',
        'HEADER')

    bind_unbind_dev(
        device_keys,
        app_keys,
        expected=devices * apps,
        as_admin=True,
        req_type='bind',
        admin_id=app_admin_id,
        admin_key=app_admin_key,
        )

    log('---------------> NON AUTONOMOUS APPS TRY TO UNBIND ', 'HEADER')

    non_autonomous_bind_unbind(device_keys, app_keys, 'unbind')

    log('---------------> APPS UNFOLLOW DEVICES USING ADMIN APIKEY',
        'HEADER')

    unfollow_dev(
        device_keys,
        app_keys,
        as_admin=True,
        permission='read',
        admin_id=app_admin_id,
        admin_key=app_admin_key,
        )

    print '''

'''
    log('''------------------------- FOLLOW REQUESTS API -------------------------

''',
        'GREEN')

    cleanup()

    log('---------------> FOLLOW REQUESTS AS ADMIN ', 'HEADER')

    follow_dev(
        device_keys,
        app_keys,
        as_admin=True,
        permission='read',
        admin_id=app_admin_id,
        admin_key=app_admin_key,
        )

    non_autonomous_follow_status(device_keys, app_keys,
                                 req_type='requests')

    print '''

'''
    log('''------------------------- FOLLOW STATUS API -------------------------

''',
        'GREEN')

    cleanup()

    log('---------------> FOLLOW REQUESTS AS ADMIN ', 'HEADER')

    follow_dev(
        device_keys,
        app_keys,
        as_admin=True,
        permission='read',
        admin_id=app_admin_id,
        admin_key=app_admin_key,
        )

    non_autonomous_follow_status(device_keys, app_keys,
                                 req_type='status')

    print '''

'''
    log('''------------------------- REJECT FOLLOW API -------------------------

''',
        'GREEN')

    cleanup()

    log('---------------> FOLLOW REQUESTS AS ADMIN ', 'HEADER')

    follow_dev(
        device_keys,
        app_keys,
        as_admin=True,
        permission='read',
        admin_id=app_admin_id,
        admin_key=app_admin_key,
        )

    non_autonomous_reject_follow(device_keys, dev_admin_id,
                                 dev_admin_key)

def security_tests():

    print '''

'''
    log('''========================= SECURITY TESTS =========================

''',
        'GREEN', modifier='BOLD')

    devices = random.randint(2, 5)
    apps = random.randint(2, 5)

    (dev_admin_id, dev_admin_key) = gen_owner()
    (app_admin_id, app_admin_key) = gen_owner()

    reg_time = time.time()
    (device_keys, app_keys) = registrations(
        devices,
        apps,
        dev_admin_id,
        dev_admin_key,
        app_admin_id,
        app_admin_key,
        )
    reg_time = time.time() - reg_time

    # Trying to register an owner from outside the localhost

    # logger.info(colour.HEADER + "---------------> OWNER REGISTRATION FROM OUTSIDE LOCALHOST " + colour.ENDC)

    # r = register_owner(admin_key, "owner"+dummy_id)
    # check(r,403)
    # logger.info("Received 403: OK")

    test_time = time.time()

    # Invalid apikey tests

    invalid_apikey(
       devices,
       apps,
       device_keys,
       app_keys,
       dev_admin_id,
       dev_admin_key,
       app_admin_id,
       app_admin_key,
       )

    # Invalid ID tests

    invalid_id(
       devices,
       apps,
       device_keys,
       app_keys,
       dev_admin_id,
       dev_admin_key,
       app_admin_id,
       app_admin_key,
       )

    # Invalid publish

    invalid_publish(
       devices,
       apps,
       device_keys,
       app_keys,
       dev_admin_id,
       dev_admin_key,
       app_admin_id,
       app_admin_key,
       )

    # Invalid subscribe

    invalid_subscribe(
       devices,
       apps,
       device_keys,
       app_keys,
       dev_admin_id,
       dev_admin_key,
       app_admin_id,
       app_admin_key,
       )

    # Invalid bind

    invalid_bind(
       devices,
       apps,
       device_keys,
       app_keys,
       dev_admin_id,
       dev_admin_key,
       app_admin_id,
       app_admin_key,
       )

    # Invalid unbind

    invalid_unbind(
       devices,
       apps,
       device_keys,
       app_keys,
       dev_admin_id,
       dev_admin_key,
       app_admin_id,
       app_admin_key,
       )

    # Invalid follow

    invalid_follow(
       devices,
       apps,
       device_keys,
       app_keys,
       dev_admin_id,
       dev_admin_key,
       app_admin_id,
       app_admin_key,
       )

    # Invalid unfollow

    invalid_unfollow(
       devices,
       apps,
       device_keys,
       app_keys,
       dev_admin_id,
       dev_admin_key,
       app_admin_id,
       app_admin_key,
       )

    # Invalid deregistrations

    invalid_deregistrations(
       devices,
       apps,
       device_keys,
       app_keys,
       dev_admin_id,
       dev_admin_key,
       app_admin_id,
       app_admin_key,
       )

    #Private exchange test cases

    private_exchange_tests(
       devices,
       apps,
       device_keys,
       app_keys,
       dev_admin_id,
       dev_admin_key,
       app_admin_id,
       app_admin_key,
       )

    is_autonomous(devices, apps)

    test_time = time.time() - test_time

    dereg_time = time.time()
    deregistrations(
        device_keys,
        app_keys,
        dev_admin_id,
        dev_admin_key,
        app_admin_id,
        app_admin_key,
        )

    dereg_time = time.time() - dereg_time

    time_list = [reg_time, test_time, dereg_time]

    output.put(time_list)


def follow_with_read(
    devices,
    apps,
    device_keys,
    app_keys,
    dev_admin_id,
    dev_admin_key,
    app_admin_id,
    app_admin_key,
    ):

    print '''

'''
    log('''------------------------- SIMPLE READ FOLLOW-SHARE -------------------------

''',
        'GREEN')

    # Follow requests from apps to devices using apps' respective apikeys

    log('---------------> FOLLOW REQUESTS WITH READ PERMISSION ',
        'HEADER')
    follow_dev(device_keys, app_keys, as_admin=False, permission='read')

    # Devices read all follow requests and share with apps

    log('---------------> DEVICES READ FOLLOW REQUESTS AND ISSUE SHARE TO APPS'
        , 'HEADER')

    share_dev(device_keys, apps)

    # Apps bind to devices' queues

    log('---------------> APPS BIND TO DEVICES', 'HEADER')
    bind_unbind_dev(device_keys, app_keys, expected=devices,
                    as_admin=False, req_type='bind')

    # Devices publish data

    log('---------------> DEVICES PUBLISH DATA', 'HEADER')
    dev_publish(device_keys)

    # Apps subscribe to messages

    log('---------------> APPS TRY TO READ PUBLISHED DATA', 'HEADER')
    app_subscribe(devices, app_keys, devices)

    # Apps unbind from devices

    log('---------------> APPS UNBIND FROM DEVICES', 'HEADER')
    bind_unbind_dev(device_keys, app_keys, expected=devices,
                    as_admin=False, req_type='unbind')

    # Devices again publish messages

    log('---------------> DEVICES PUBLISH DATA', 'HEADER')
    dev_publish(device_keys)

    # Apps try to subscribe

    log('---------------> APPS TRY TO READ PUBLISHED DATA', 'HEADER')
    app_subscribe(devices, app_keys, 0)

    # Apps unfollow devices

    log('---------------> APPS WITH READ ACCESS UNFOLLOW DEVICES',
        'HEADER')
    unfollow_dev(device_keys, app_keys, as_admin=False,
                 permission='read')


def follow_as_admin(
    devices,
    apps,
    device_keys,
    app_keys,
    dev_admin_id,
    dev_admin_key,
    app_admin_id,
    app_admin_key,
    ):

    print '''

'''
    log('''------------------------- FOLLOW REQUESTS AS ADMIN -------------------------

''',
        'GREEN')

    # Follow requests as admin....

    log('---------------> FOLLOW REQUESTS WITH READ PERMISSION AS ADMIN'
        , 'HEADER')

    follow_dev(
        device_keys,
        app_keys,
        as_admin=True,
        permission='read',
        admin_id=app_admin_id,
        admin_key=app_admin_key,
        )

    # Devices share with apps

    log('---------------> DEVICES READ FOLLOW REQUESTS AND ISSUE SHARE TO APPS'
        , 'HEADER')

    share_dev(device_keys, apps)

    # Apps bind to devices' queues

    log('---------------> APPS BIND TO DEVICES', 'HEADER')
    bind_unbind_dev(device_keys, app_keys, expected=devices,
                    as_admin=False, req_type='bind')

    # Devices publish data

    log('---------------> DEVICES PUBLISH DATA', 'HEADER')
    dev_publish(device_keys)

    # Apps subscribe to messages

    log('---------------> APPS TRY TO READ PUBLISHED DATA', 'HEADER')
    app_subscribe(devices, app_keys, devices)

    # Apps unfollow all devices

    log('---------------> APPS UNFOLLOW ALL DEVICES USING THEIR ADMIN APIKEYS'
        , 'HEADER')
    unfollow_dev(
        device_keys,
        app_keys,
        as_admin=True,
        permission='read',
        admin_id=app_admin_id,
        admin_key=app_admin_key,
        )

    # Apps try to bind to unfollowed devices

    log('---------------> APPS TRY TO BIND TO UNFOLLOWED DEVICES',
        'HEADER')
    bind_unbind_without_follow(device_keys, app_keys, as_admin=False,
                               req_type='bind')


def follow_with_write(
    devices,
    apps,
    device_keys,
    app_keys,
    dev_admin_id,
    dev_admin_key,
    app_admin_id,
    app_admin_key,
    ):

    print '''

'''
    log('''------------------------- FOLLOW REQUESTS WITH WRITE PERMISSION -------------------------

''',
        'GREEN')

    # Follow requests for write....

    log('---------------> FOLLOW REQUESTS WITH WRITE PERMISSIONS',
        'HEADER')
    follow_dev(device_keys, app_keys, as_admin=False, permission='write'
               )

    # Devices share with apps with write access

    log('---------------> DEVICES READ FOLLOW REQUESTS AND ISSUE SHARE TO APPS'
        , 'HEADER')
    share_dev(device_keys, apps)

    # Apps publish to command queue of devices

    log('---------------> APPS PUBLISH TO COMMAND EXCHANGE OF DEVICES',
        'HEADER')
    app_publish(device_keys, app_keys, 202)

    # Devices subscribe to their command queue

    log('---------------> DEVICES SUBSCRIBE TO THEIR COMMAND QUEUES',
        'HEADER')
    dev_subscribe(apps, device_keys, apps)

    # Follow requests for write....

    log('---------------> APPS WITH WRITE ACCESS UNFOLLOW DEVICES',
        'HEADER')
    unfollow_dev(device_keys, app_keys, as_admin=False,
                 permission='write')

    # Apps publish to command queue of devices

    log('---------------> APPS TRY TO PUBLISH TO COMMAND EXCHANGE OF UNFOLLOWED DEVICES'
        , 'HEADER')
    app_publish(device_keys, app_keys, 202)


def follow_with_read_write(
    devices,
    apps,
    device_keys,
    app_keys,
    dev_admin_id,
    dev_admin_key,
    app_admin_id,
    app_admin_key,
    ):

    print '''

'''
    log('''------------------------- FOLLOW REQUESTS WITH READ-WRITE PERMISSIONS -------------------------

''',
        'GREEN')

    # Apps request follow with read-write permissions

    log('---------------> APPS REQUEST FOLLOW WITH READ-WRITE PERMISSIONS'
        , 'HEADER')
    follow_dev(device_keys, app_keys, as_admin=False,
               permission='read-write')

    # Devices approve issue share to apps

    log('---------------> DEVICES APPROVE READ-WRITE FOLLOW REQUESTS WITH SHARE'
        , 'HEADER')
    share_dev(device_keys, apps * 2)

    # Apps publish to command queue of devices

    log('---------------> APPS PUBLISH TO COMMAND EXCHANGE OF DEVICES',
        'HEADER')
    app_publish(device_keys, app_keys, 202)

    # Devices subscribe to their command queue

    log('---------------> DEVICES SUBSCRIBE TO THEIR COMMAND QUEUES',
        'HEADER')
    dev_subscribe(apps, device_keys, apps)

    # Apps bind to devices' queues

    log('---------------> APPS BIND TO DEVICES', 'HEADER')
    bind_unbind_dev(device_keys, app_keys, expected=2 * devices,
                    as_admin=False, req_type='bind')

    # Devices publish again

    log('---------------> DEVICES PUBLISH DATA', 'HEADER')
    dev_publish(device_keys)

    # Apps subscribe to messages

    log('---------------> APPS TRY TO READ PUBLISHED DATA', 'HEADER')
    app_subscribe(devices, app_keys, devices)

    # Apps relinquish write permission

    log('---------------> APPS UNFOLLOW DEVICES FOR WRITE PERMISSION',
        'HEADER')
    unfollow_dev(device_keys, app_keys, as_admin=False,
                 permission='write')

    # Apps publish to command queue of devices

    log('---------------> APPS TRY TO PUBLISH TO COMMAND EXCHANGE OF UNFOLLOWED DEVICES'
        , 'HEADER')
    app_publish(device_keys, app_keys, 202)

    # Devices publish again

    log('---------------> DEVICES PUBLISH DATA AFTER WRITE UNFOLLOW',
        'HEADER')
    dev_publish(device_keys)

    # Apps subscribe to messages

    log('---------------> APPS TRY TO READ PUBLISHED DATA AFTER WRITE UNFOLLOW'
        , 'HEADER')
    app_subscribe(devices, app_keys, devices)

    # Apps unfollow with read permissions

    log('---------------> APPS UNFOLLOW DEVICES WITH READ PERMISSION',
        'HEADER')
    unfollow_dev(
        device_keys,
        app_keys,
        as_admin=True,
        permission='read',
        admin_id=app_admin_id,
        admin_key=app_admin_key,
        )

    # Apps try to bind to unfollowed devices

    log('---------------> APPS TRY TO BIND TO UNFOLLOWED DEVICES',
        'HEADER')
    bind_unbind_without_follow(device_keys, app_keys, as_admin=False,
                               req_type='bind')


def bind_as_admin(
    devices,
    apps,
    device_keys,
    app_keys,
    dev_admin_id,
    dev_admin_key,
    app_admin_id,
    app_admin_key,
    ):

    print '''

'''
    log('''------------------------- BIND USING ADMIN APIKEY -------------------------

''',
        'GREEN')

    # Apps obtain read-write follow

    log('---------------> APPS FOLLOW WITH READ-WRITE PERMISSIONS',
        'HEADER')
    follow_dev(device_keys, app_keys, as_admin=False,
               permission='read-write')

    # Devices approve issue share to apps

    log('---------------> DEVICES APPROVE READ-WRITE FOLLOW REQUESTS WITH SHARE'
        , 'HEADER')
    share_dev(device_keys, apps * 2)

    # Apps bind to devices again but this time using admin apikey

    log('---------------> APPS BIND TO DEVICES USING ADMIN APIKEY',
        'HEADER')

    bind_unbind_dev(
        device_keys,
        app_keys,
        expected=devices * apps * 2,
        as_admin=True,
        req_type='bind',
        admin_id=app_admin_id,
        admin_key=app_admin_key,
        )

    # Devices publish again

    log('---------------> DEVICES PUBLISH DATA', 'HEADER')
    dev_publish(device_keys)

    # Apps subscribe to messages

    log('---------------> APPS TRY TO READ PUBLISHED DATA', 'HEADER')
    app_subscribe(devices, app_keys, devices)

    # Unbind from devices as admin

    log('---------------> APPS UNBIND FROM DEVICES USING ADMIN APIKEY',
        'HEADER')

    bind_unbind_dev(
        device_keys,
        app_keys,
        expected=devices * apps * 2,
        as_admin=True,
        req_type='unbind',
        admin_id=app_admin_id,
        admin_key=app_admin_key,
        )

    # Devices now publish data

    log('---------------> DEVICES PUBLISH DATA', 'HEADER')
    dev_publish(device_keys)

    # Apps try to subscribe but get 0 messages

    log('---------------> APPS TRY TO READ PUBLISHED DATA', 'HEADER')
    app_subscribe(devices, app_keys, 0)

    # Apps unfollow all devices

    log('---------------> APPS UNFOLLOW ALL DEVICES USING THEIR RESPECTIVE APIKEYS'
        , 'HEADER')
    unfollow_dev(device_keys, app_keys, as_admin=False,
                 permission='read-write')

    # Apps try to bind to unfollowed devices

    log('---------------> APPS TRY TO BIND TO UNFOLLOWED DEVICES',
        'HEADER')
    bind_unbind_without_follow(
        device_keys,
        app_keys,
        as_admin=True,
        req_type='bind',
        admin_id=app_admin_id,
        admin_key=app_admin_key,
        )


def diagnostic_tests(
    devices,
    apps,
    device_keys,
    app_keys,
    dev_admin_id,
    dev_admin_key,
    app_admin_id,
    app_admin_key,
    ):

    # ===============================Diagnostics channel ===============================

    # Follow requests from apps to devices using apps' respective apikeys for diagnostics
    # channel

    print '''

'''
    log('''------------------------- DIAGNOSTICS CHANNEL TESTS -------------------------

''',
        'GREEN')

    log('---------------> FOLLOW REQUESTS WITH READ PERMISSION TO DIAGNOSTICS CHANNEL'
        , 'HEADER')
    follow_dev(device_keys, app_keys, as_admin=False, permission='read'
               , message_type='diagnostics')

    # Devices read all follow requests and share with apps

    log('---------------> DEVICES READ FOLLOW REQUESTS AND ISSUE SHARE TO APPS'
        , 'HEADER')

    share_dev(device_keys, apps)

    # Apps bind to devices' diagnostics exchanges

    log("---------------> APPS BIND TO DEVICES' DIAGNOSTICS CHANNEL",
        'HEADER')
    bind_unbind_dev(
        device_keys,
        app_keys,
        expected=devices,
        as_admin=False,
        req_type='bind',
        message_type='diagnostics',
        )

    # Devices publish data to diagnostics exchanges

    log('---------------> DEVICES PUBLISH DATA TO DIAGNOSTICS CHANNEL',
        'HEADER')
    dev_publish(device_keys, message_type='diagnostics')

    # Apps subscribe to messages

    log('---------------> APPS TRY TO READ PUBLISHED DATA', 'HEADER')
    app_subscribe(devices, app_keys, devices)

    # Apps unbind from devices diagnostics channel

    log("---------------> APPS UNBIND FROM DEVICES' DIAGNOSTICS CHANNEL"
        , 'HEADER')
    bind_unbind_dev(
        device_keys,
        app_keys,
        expected=devices,
        as_admin=False,
        req_type='unbind',
        message_type='diagnostics',
        )

    # Devices again publish messages to diagnostics channel

    log('---------------> DEVICES PUBLISH DATA TO DIAGNOSTICS CHANNEL',
        'HEADER')
    dev_publish(device_keys, message_type='diagnostics')

    # Apps try to subscribe

    log('---------------> APPS TRY TO READ PUBLISHED DATA', 'HEADER')
    app_subscribe(devices, app_keys, 0)

    # Apps bind to devices using admin apikey

    log('---------------> APPS BIND TO DEVICES USING ADMIN APIKEY',
        'HEADER')

    bind_unbind_dev(
        device_keys,
        app_keys,
        expected=devices * apps,
        as_admin=True,
        req_type='bind',
        message_type='diagnostics',
        admin_id=app_admin_id,
        admin_key=app_admin_key,
        )

    # Devices publish again to diagnostics channel

    log('---------------> DEVICES PUBLISH DATA TO DIAGNOSTICS CHANNEL',
        'HEADER')
    dev_publish(device_keys, message_type='diagnostics')

    # Apps subscribe to messages

    log('---------------> APPS TRY TO READ PUBLISHED DATA', 'HEADER')
    app_subscribe(devices, app_keys, devices)

    # Unbind from devices as admin

    log('---------------> APPS UNBIND FROM DEVICES USING ADMIN APIKEY',
        'HEADER')

    bind_unbind_dev(
        device_keys,
        app_keys,
        expected=devices * apps,
        as_admin=True,
        req_type='unbind',
        message_type='diagnostics',
        admin_id=app_admin_id,
        admin_key=app_admin_key,
        )

    # Devices now publish data to diagnostics channel

    log('---------------> DEVICES PUBLISH DATA TO DIAGNOSTICS CHANNEL',
        'HEADER')
    dev_publish(device_keys, message_type='diagnostics')

    # Apps try to subscribe but get 0 messages

    log('---------------> APPS TRY TO READ PUBLISHED DATA', 'HEADER')
    app_subscribe(devices, app_keys, 0)

    # Apps unfollow all devices

    log('---------------> APPS UNFOLLOW ALL DEVICES USING THEIR RESPECTIVE APIKEYS'
        , 'HEADER')
    unfollow_dev(device_keys, app_keys, as_admin=False,
                 permission='read', message_type='diagnostics')

    # Apps try to bind to unfollowed devices' diagnostics channel

    log("---------------> APPS TRY TO BIND TO UNFOLLOWED DEVICES' DIAGNOSTICS CHANNEL"
        , 'HEADER')
    bind_unbind_without_follow(device_keys, app_keys, as_admin=False,
                               req_type='bind',
                               message_type='diagnostics')


def priority_tests(
    devices,
    apps,
    device_keys,
    app_keys,
    dev_admin_id,
    dev_admin_key,
    app_admin_id,
    app_admin_key,
    ):

    # ===============================Priority queue ===============================

    print '''

'''
    log('''------------------------- PRIORITY QUEUE TESTS -------------------------

''',
        'GREEN')

    # Follow requests from apps to devices using apps' respective apikeys

    log('---------------> FOLLOW REQUESTS WITH READ PERMISSION',
        'HEADER')
    follow_dev(device_keys, app_keys, as_admin=False, permission='read')

    # Devices read all follow requests and share with apps

    log('---------------> DEVICES READ FOLLOW REQUESTS AND ISSUE SHARE TO APPS'
        , 'HEADER')

    share_dev(device_keys, apps)

    # Apps bind to devices' diagnostics exchanges

    log('---------------> APPS BIND TO DEVICES PROTECTED CHANNEL',
        'HEADER')

    bind_unbind_dev(
        device_keys,
        app_keys,
        expected=devices,
        as_admin=False,
        req_type='bind',
        is_priority='true',
        )

    # Devices publish data to diagnostics exchanges

    log('---------------> DEVICES PUBLISH DATA', 'HEADER')
    dev_publish(device_keys)

    # Apps subscribe to messages

    log('---------------> APPS TRY TO READ PUBLISHED DATA', 'HEADER')
    app_subscribe(devices, app_keys, devices, message_type='priority')

    # Apps unbind from devices diagnostics channel

    log('---------------> APPS UNBIND FROM DEVICES', 'HEADER')
    bind_unbind_dev(
        device_keys,
        app_keys,
        expected=devices,
        as_admin=False,
        req_type='unbind',
        is_priority='true',
        )

    # Devices again publish messages to diagnostics channel

    log('---------------> DEVICES PUBLISH DATA', 'HEADER')
    dev_publish(device_keys)

    # Apps try to subscribe

    log('---------------> APPS TRY TO READ PUBLISHED DATA', 'HEADER')
    app_subscribe(devices, app_keys, 0, message_type='priority')

    # Apps bind to devices using admin apikey

    log('---------------> APPS BIND TO DEVICES USING ADMIN APIKEY',
        'HEADER')

    bind_unbind_dev(
        device_keys,
        app_keys,
        expected=devices * apps,
        as_admin=True,
        req_type='bind',
        is_priority='true',
        admin_id=app_admin_id,
        admin_key=app_admin_key,
        )

    # Devices publish again to diagnostics channel

    log('---------------> DEVICES PUBLISH DATA', 'HEADER')
    dev_publish(device_keys)

    # Apps subscribe to messages

    log('---------------> APPS TRY TO READ PUBLISHED DATA', 'HEADER')
    app_subscribe(devices, app_keys, devices, message_type='priority')

    # Unbind from devices as admin

    log('---------------> APPS UNBIND FROM DEVICES USING ADMIN APIKEY',
        'HEADER')

    bind_unbind_dev(
        device_keys,
        app_keys,
        expected=devices * apps,
        as_admin=True,
        req_type='unbind',
        is_priority='true',
        admin_id=app_admin_id,
        admin_key=app_admin_key,
        )

    # Devices now publish data to diagnostics channel

    log('---------------> DEVICES PUBLISH DATA', 'HEADER')
    dev_publish(device_keys)

    # Apps try to subscribe but get 0 messages

    log('---------------> APPS TRY TO READ PUBLISHED DATA', 'HEADER')
    app_subscribe(devices, app_keys, 0, message_type='priority')

    # Apps unfollow all devices

    log('---------------> APPS UNFOLLOW ALL DEVICES USING THEIR RESPECTIVE APIKEYS'
        , 'HEADER')
    unfollow_dev(device_keys, app_keys, as_admin=False,
                 permission='read')

    # Apps try to bind to unfollowed devices' diagnostics channel

    log("---------------> APPS TRY TO BIND TO UNFOLLOWED DEVICES' PRIORITY CHANNEL"
        , 'HEADER')
    bind_unbind_without_follow(device_keys, app_keys, as_admin=False,
                               req_type='bind', is_priority='true')


def amqp_tests(
    devices,
    apps,
    device_keys,
    app_keys,
    dev_admin_id,
    dev_admin_key,
    app_admin_id,
    app_admin_key,
    ):

    # =============================== AMQP TESTS===============================

    print '''

'''
    log('''------------------------- AMQP TESTS -------------------------

''',
        'GREEN')

    # Apps request follow with read-write permissions

    log('---------------> APPS REQUEST FOLLOW WITH READ-WRITE PERMISSIONS'
        , 'HEADER')
    follow_dev(device_keys, app_keys, as_admin=False,
               permission='read-write')

    # Devices approve issue share to apps

    log('---------------> DEVICES APPROVE READ-WRITE FOLLOW REQUESTS WITH SHARE'
        , 'HEADER')
    share_dev(device_keys, apps * 2)

    # Apps publish to command queue of devices

    log('---------------> APPS PUBLISH TO COMMAND EXCHANGE OF DEVICES',
        'HEADER')
    app_publish_amqp(device_keys, app_keys)

    # Devices subscribe to their command queue

    log('---------------> DEVICES SUBSCRIBE TO THEIR COMMAND QUEUES',
        'HEADER')
    dev_subscribe_amqp(apps, device_keys, apps)

    # Apps bind to devices' queues

    log('---------------> APPS BIND TO DEVICES', 'HEADER')
    bind_unbind_dev(device_keys, app_keys, expected=2 * devices,
                    as_admin=False, req_type='bind')

    # Devices now publish

    log('---------------> DEVICES PUBLISH DATA', 'HEADER')
    dev_publish_amqp(device_keys)

    # Apps subscribe to messages

    log('---------------> APPS TRY TO READ PUBLISHED DATA', 'HEADER')
    app_subscribe_amqp(devices, app_keys, devices)

    # Apps relinquish write permission

    log('---------------> APPS WITH WRITE ACCESS UNFOLLOW DEVICES',
        'HEADER')
    unfollow_dev(device_keys, app_keys, as_admin=False,
                 permission='write')

    # Apps publish to command queue of devices

    log('---------------> APPS TRY TO PUBLISH TO COMMAND EXCHANGE OF UNFOLLOWED DEVICES'
        , 'HEADER')
    app_publish_amqp(device_keys, app_keys)

    # Devices subscribe to their command queue after write unfollow by apps

    log('---------------> DEVICES SUBSCRIBE TO THEIR COMMAND QUEUES AFTER WRITE UNFOLLOW BY APPS'
        , 'HEADER')
    dev_subscribe_amqp(apps, device_keys, 0)

    # Devices publish again

    log('---------------> DEVICES PUBLISH DATA AFTER WRITE UNFOLLOW',
        'HEADER')
    dev_publish_amqp(device_keys)

    # Apps subscribe to messages

    log('---------------> APPS TRY TO READ PUBLISHED DATA AFTER WRITE UNFOLLOW'
        , 'HEADER')
    app_subscribe_amqp(devices, app_keys, devices)

    # Apps unfollow with read permissions

    log('---------------> APPS UNFOLLOW DEVICES WITH READ ACCESS',
        'HEADER')
    unfollow_dev(
        device_keys,
        app_keys,
        as_admin=True,
        permission='read',
        admin_id=app_admin_id,
        admin_key=app_admin_key,
        )

    # Apps try to bind to unfollowed devices

    log('---------------> APPS TRY TO BIND TO UNFOLLOWED DEVICES',
        'HEADER')
    bind_unbind_without_follow(device_keys, app_keys, as_admin=False,
                               req_type='bind')


def public_exchange_tests(
    devices,
    apps,
    device_keys,
    app_keys,
    dev_admin_id,
    dev_admin_key,
    app_admin_id,
    app_admin_key,
    ):

    print '''

'''
    log('''------------------------- PUBLIC EXCHANGE TESTS -------------------------

''',
        'GREEN')

    # Apps bind to devices' queues

    log('---------------> APPS BIND TO DEVICES', 'HEADER')
    bind_unbind_dev(
        device_keys,
        app_keys,
        expected=devices,
        as_admin=False,
        req_type='bind',
        message_type='public',
        )

    # Devices publish data

    log('---------------> DEVICES PUBLISH DATA', 'HEADER')
    dev_publish(device_keys, message_type='public')

    # Apps subscribe to messages

    log('---------------> APPS TRY TO READ PUBLISHED DATA', 'HEADER')
    app_subscribe(devices, app_keys, devices)

    # Apps unbind from devices

    log('---------------> APPS UNBIND FROM DEVICES', 'HEADER')
    bind_unbind_dev(
        device_keys,
        app_keys,
        expected=devices,
        as_admin=False,
        req_type='unbind',
        message_type='public',
        )

    # Devices again publish messages

    log('---------------> DEVICES PUBLISH DATA', 'HEADER')
    dev_publish(device_keys, message_type='public')

    # Apps try to subscribe

    log('---------------> APPS TRY TO READ PUBLISHED DATA', 'HEADER')
    app_subscribe(devices, app_keys, 0)

    # -------------------------Using admin apikey----------------------

    # Apps bind to devices using admin apikey

    log('---------------> APPS BIND TO DEVICES USING ADMIN APIKEY',
        'HEADER')
    bind_unbind_dev(
        device_keys,
        app_keys,
        expected=devices,
        as_admin=True,
        req_type='bind',
        message_type='public',
        admin_id=app_admin_id,
        admin_key=app_admin_key,
        )

    # Devices publish data

    log('---------------> DEVICES PUBLISH DATA', 'HEADER')
    dev_publish(device_keys, message_type='public')

    # Apps subscribe to messages

    log('---------------> APPS TRY TO READ PUBLISHED DATA', 'HEADER')
    app_subscribe(devices, app_keys, devices)

    # Apps unbind from devices using admin apikey

    log('---------------> APPS UNBIND FROM DEVICES', 'HEADER')
    bind_unbind_dev(
        device_keys,
        app_keys,
        expected=devices,
        as_admin=True,
        req_type='unbind',
        message_type='public',
        admin_id=app_admin_id,
        admin_key=app_admin_key,
        )

    # Devices again publish messages

    log('---------------> DEVICES PUBLISH DATA', 'HEADER')
    dev_publish(device_keys, message_type='public')

    # Apps try to subscribe

    log('---------------> APPS TRY TO READ PUBLISHED DATA', 'HEADER')
    app_subscribe(devices, app_keys, 0)


def functional_tests(*args):

    if type(args[0]) is list:
        devices = args[0][0]
        apps = args[0][1]
    else:

        devices = args[0]
        apps = args[1]

    (dev_admin_id, dev_admin_key) = gen_owner()
    (app_admin_id, app_admin_key) = gen_owner()

    print '''

'''
    log('''========================= FUNCTIONAL TESTS =========================

''',
        'GREEN', modifier='BOLD')

    reg_time = time.time()
    (device_keys, app_keys) = registrations(
        devices,
        apps,
        dev_admin_id,
        dev_admin_key,
        app_admin_id,
        app_admin_key,
        )
    reg_time = time.time() - reg_time

    check_register(device_keys, app_keys)

    test_time = time.time()

    # Read follow requests. Also tests bind using admin keys

    follow_with_read(
        devices,
        apps,
        device_keys,
        app_keys,
        dev_admin_id,
        dev_admin_key,
        app_admin_id,
        app_admin_key,
        )

    # Follow requests as admin

    follow_as_admin(
        devices,
        apps,
        device_keys,
        app_keys,
        dev_admin_id,
        dev_admin_key,
        app_admin_id,
        app_admin_key,
        )

    # Follow with write

    follow_with_write(
        devices,
        apps,
        device_keys,
        app_keys,
        dev_admin_id,
        dev_admin_key,
        app_admin_id,
        app_admin_key,
        )

    # Follow requests with read-write permissions

    follow_with_read_write(
        devices,
        apps,
        device_keys,
        app_keys,
        dev_admin_id,
        dev_admin_key,
        app_admin_id,
        app_admin_key,
        )

    # Bind and unbind as admin

    bind_as_admin(
        devices,
        apps,
        device_keys,
        app_keys,
        dev_admin_id,
        dev_admin_key,
        app_admin_id,
        app_admin_key,
        )

    # Diagnostic channel tests

    diagnostic_tests(
        devices,
        apps,
        device_keys,
        app_keys,
        dev_admin_id,
        dev_admin_key,
        app_admin_id,
        app_admin_key,
        )

    # Priority queue tests

    priority_tests(
        devices,
        apps,
        device_keys,
        app_keys,
        dev_admin_id,
        dev_admin_key,
        app_admin_id,
        app_admin_key,
        )

    # Public exchange tests

    public_exchange_tests(
        devices,
        apps,
        device_keys,
        app_keys,
        dev_admin_id,
        dev_admin_key,
        app_admin_id,
        app_admin_key,
        )

    # AMQP tests

    amqp_tests(
        devices,
        apps,
        device_keys,
        app_keys,
        dev_admin_id,
        dev_admin_key,
        app_admin_id,
        app_admin_key,
        )


    test_time = time.time() - test_time

    dereg_time = time.time()

    # Deregister all devices and apps

    deregistrations(
        device_keys,
        app_keys,
        dev_admin_id,
        dev_admin_key,
        app_admin_id,
        app_admin_key,
        )

    dereg_time = time.time() - dereg_time

    check_deregister(device_keys, app_keys)

    time_list = [reg_time, test_time, dereg_time]

    output.put(time_list)


def concurrency_tests():

    concurrent_processes = random.randint(2, 7)

    num_list = []

    for num in range(concurrent_processes):

        devices = random.randint(2, 7)
        apps = random.randint(2, 7)

        num_list.append([devices, apps])

    #processes = [mp.Process(target=functional_tests, args=(num, ))
    #             for num in num_list]

    #for p in processes:
    #    p.start()

    #for p in processes:
    #    p.join()

    pool    = mp.Pool(concurrent_processes)
    result  = pool.map(functional_tests, num_list)

    i = 1

    print '''

'''
    log('=========================All tests have passed========================='
        , 'GREEN', modifier='BOLD')

    while i <= concurrent_processes :

        time_list = output.get()

        print '''

'''
        log('------------------------- Process ' + str(i)
            + ''' -------------------------

''', 'GREEN')
        log("Time taken for registrations    :	    "
            + str(time_list[0]) + 's', 'GREEN')
        log("Time taken for test cases       :	    "
            + str(time_list[1]) + 's', 'GREEN')
        log("Time taken for deregistrations  :	    "
            + str(time_list[2]) + 's', 'GREEN')

        i = i + 1

    sys.exit(0)


def start_tests(devices, apps, args):

    if args.choice == 'fxnl':

        functional_tests(devices, apps)
        time_list = output.get()
    elif args.choice == 'sec':

        security_tests()
        time_list = output.get()
    elif args.choice == 'concr':

        concurrency_tests()

    print '''

'''
    log('=========================All tests have passed========================='
        , 'GREEN', modifier='BOLD')
    log("Time taken for registrations    :	    " + str(time_list[0])
        + 's', 'GREEN')
    log("Time taken for test cases       :	    " + str(time_list[1])
        + 's', 'GREEN')
    log("Time taken for deregistrations  :	    " + str(time_list[2])
        + 's', 'GREEN')


if __name__ == '__main__':

    parser = \
        argparse.ArgumentParser(description='Test cases for Corinthian')
    subparser = parser.add_subparsers(dest='choice')

    func_parser = subparser.add_parser('fxnl',
            help='Performs functional tests')

    func_parser.add_argument(
        '-d',
        '--devices',
        action='store',
        dest='devices',
        type=int,
        help='No. of devices to run the tests',
        )
    func_parser.add_argument(
        '-a',
        '--apps',
        action='store',
        dest='apps',
        type=int,
        help='No. of apps to run the tests',
        )
    func_parser.add_argument('--random', action='store_true',
                             help='Run tests with random devices and apps'
                             )

    sec_parser = subparser.add_parser('sec',
            help='Performs security tests')

    conc_parser = subparser.add_parser('concr',
            help='Performs concurrency tests')

    conc_parser.add_argument(
        '-d',
        '--devices',
        action='store',
        dest='devices',
        type=int,
        help='No. of devices to run the tests',
        )
    conc_parser.add_argument(
        '-a',
        '--apps',
        action='store',
        dest='apps',
        type=int,
        help='No. of apps to run the tests',
        )
    conc_parser.add_argument('--random', action='store_true',
                             help='Run tests with random devices and apps'
                             )

    all_parser = subparser.add_parser('all',
            help='Performs all of the above tests')

    all_parser.add_argument(
        '-d',
        '--devices',
        action='store',
        dest='devices',
        type=int,
        help='No. of devices to run the tests',
        )
    all_parser.add_argument(
        '-a',
        '--apps',
        action='store',
        dest='apps',
        type=int,
        help='No. of apps to run the tests',
        )
    all_parser.add_argument('--random', action='store_true',
                            help='Run tests with random devices and apps'
                            )

    args = parser.parse_args()

    devices = 0
    apps = 0

    if args.choice != 'sec':

        if args.random:
            devices = random.randint(10, 20)
            apps = random.randint(10, 20)
        else:
            devices = args.devices
            apps = args.apps

    logging.basicConfig(format='%(asctime)s %(levelname)-6s %(message)s'
                        , level=logging.DEBUG,
                        datefmt='%Y-%m-%d %H:%M:%S')
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('pika').setLevel(logging.CRITICAL)

    start_tests(devices, apps, args)

