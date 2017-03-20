from flask import Flask, render_template, redirect, request, url_for, make_response
# from PacketHandler import PacketHandler, DeviceHandler
from pysharktests.interfaces import *
import pandas as pd

app = Flask(__name__)
app.config.from_object('config.TestConfig')


@app.route('/')
def start():
    return redirect(url_for('index'))


@app.route('/index')
def index():
    return render_template("index.html")


@app.route('/about')
def about():
    # return 'About Page'
    # my_p = PacketHandler()
    #  myvalue =my_p.get_all_devices()
    return render_template("about.html")


@app.route('/interfaces', methods=['post', 'get'])
# @app.route('/interfaces/<device>/')
def interfaces(all_devices=None, active_devices=None):
    # device_handler = DeviceHandler()
    # all_devices = device_handler.get_interfaces()
    all_devices = get_interfaces()
    active_devices = all_devices
    return render_template("interfaces.html", all_devices=all_devices, active_devices=active_devices)


@app.route('/analysishub', methods=['post', 'get'])
# @app.route('/interfaces/<device>/analysishub')
def analysishub():
    selected_interface = request.form['selected_interface']
    device = selected_interface.split()
    capture_device = device[2].strip("()")
    capture = pyshark.LiveCapture(capture_device)
    # TODO - SNIFF CONTINUOUSLY
    capture.sniff(packet_count=50, timeout=100)
    # eth, ip_info, table, udp
    eth_info, ip_info, table, tcp_info, udp_info = packet_dump(capture)
    # print("INFO OF ONE SINGLE PACKET\n", packet_total_info)
    # print(len(packet_total_info))
    #print("TABLE TEST CONTENTS\n", table_test)
    #print(len(table_test))
    print("TABLE DUMP CONTENTS\n", table)
    print(len(table))
    print("IP INFO CONTENTS\n", ip_info)
    print(len(ip_info))
    print("TCP INFO CONTENTS\n", tcp_info)
    print(len(tcp_info))
    print("UDP INFO CONTENTS\n", udp_info)
    print(len(udp_info))
    pandas_web = pd.DataFrame(table, columns=['Time', 'Source IP', 'Dest. IP', 'Protocol', 'Source MAC', 'Dest. MAC',
                                              'Source Port', 'Dest. Port'])\
        .to_html(classes=['table table-bordered table-hover table-striped'], header=True, index=True)
    return render_template("analysishub.html", pandas_web=pandas_web, ip_info=ip_info, eth_info=eth_info,
                           tcp_info=tcp_info, udp_info=udp_info)


@app.route('/help')
def help():
    return render_template("help.html")


@app.errorhandler(400)
def page_bad_request(error):
    resp = make_response(render_template('page_bad_request.html'), 400)
    resp.headers['X-Something'] = 'A value'
    # print resp
    return resp


@app.errorhandler(404)
def page_not_found(error):
    # TODO - Utilise on all functions or remove,
    resp = make_response(render_template('page_not_found.html'), 404)
    resp.headers['X-Something'] = 'A value'
    print(resp)  # <Response 1361 bytes [404 NOT FOUND]>
    return resp


with app.test_request_context():
    print(url_for('index'))
    print(url_for('interfaces', next="/"))
    print(url_for('help'))
    print(url_for('analysishub'))

if __name__ == '__main__':
    app.run()
