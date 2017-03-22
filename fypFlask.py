import pandas as pd
import pyshark
from flask import Flask, render_template, redirect, request, url_for, make_response
from Handler import DeviceHandler, CaptureHandler

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
    app.logger.log()
    app.logger.info("RENDERING: About Template")
    return render_template("about.html")


@app.route('/interfaces', methods=['post', 'get'])
def interfaces(all_devices=None, active_devices=None):
    dh = DeviceHandler()
    all_devices = dh.get_devices()
    active_devices = all_devices
    return render_template("interfaces.html", all_devices=all_devices, active_devices=active_devices)


@app.route('/analysishub', methods=['post', 'get'])
def analysishub():
    dh = DeviceHandler()
    ch = CaptureHandler()
    dev = request.form['selected_interface']
    capture_device = dh.selected_device(dev)

    capture = pyshark.LiveCapture(capture_device)
    capture.sniff(packet_count=50, timeout=100)
    eth_info, ip_info, table, tcp_info, udp_info = ch.packet_dump(capture)
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
