from flask import Flask
from flask import render_template
from flask import Markup
from PacketHandler import PacketHandler
app = Flask(__name__)


@app.route('/')
@app.route('/index')
def index():
    return render_template("index.html")


@app.route('/about')
def about():
    # return 'About Page'
    my_p = PacketHandler()
    myvalue =my_p.get_all_devices()
    return render_template("about.html", daveisalad=myvalue)


@app.route('/interfaces')
@app.route('/interfaces/<device>/')
def interfaces(device=None):
    packet_handler = PacketHandler()
    devices = packet_handler.get_all_devices()
    return render_template("interfaces.html", device=devices)

@app.route('/interfaces/<device>/analysishub')
def analysishub(device=None):
    return render_template("analysishub.html", device=device)


@app.route('/help')
def help():
    return render_template("help.html")


if __name__ == '__main__':
    app.run(debug=True)
