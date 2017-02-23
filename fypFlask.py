from flask import Flask, render_template, redirect, request, url_for, make_response
from PacketHandler import PacketHandler
app = Flask(__name__)
app.config.from_object('config.DevConfig')


@app.route('/')
def start():
    return redirect(url_for('index'))


@app.route('/index', methods=['GET'])
def index():
    if request.method == 'GET':
        return render_template("index.html")
    else:
        print ("NOT POST METHOD")


@app.route('/about')
def about():
    # return 'About Page'
  # my_p = PacketHandler()
  #  myvalue =my_p.get_all_devices()
    return render_template("about.html")


@app.route('/interfaces')
#@app.route('/interfaces/<device>/')
def interfaces(all_devices=None, active_devices=None):

    packet_handler = PacketHandler()
    all_devices = packet_handler.get_all_devices()
    if len(all_devices) <= 0:
        print("ERROR: No Devices Found")
    active_devices = packet_handler.get_active_devices()

    return render_template("interfaces.html", all_devices=all_devices, active_devices=active_devices)


@app.route('/analysishub')
@app.route('/interfaces/<device>/analysishub')
def analysishub(device=None):
    return render_template("analysishub.html", device=device)


@app.route('/help')
def help():
    return render_template("help.html")

@app.errorhandler(400)
def page_bad_request(error):
    resp = make_response(render_template('page_not_found.html'), 400)
    resp.headers['X-Something'] = 'A value'
    print resp
    return resp

@app.errorhandler(404)
def page_not_found(error):
    # TODO - Utilise on all functions or remove,
    resp = make_response(render_template('page_not_found.html'), 404)
    resp.headers['X-Something'] = 'A value'
    print resp  # <Response 1361 bytes [404 NOT FOUND]>
    return resp


with app.test_request_context():
    print url_for('index')
    print url_for('interfaces', next="/")
    print url_for('help')
    print url_for('analysishub')


if __name__ == '__main__':
    app.run()
