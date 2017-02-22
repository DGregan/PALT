from flask import Flask, render_template, Markup
from PacketHandler import PacketHandler
app = Flask(__name__)


@app.route('/')
@app.route('/index')
def index():
    return render_template("index.html")


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
    active_devices = packet_handler.get_active_devices()
    return render_template("interfaces.html", all_devices=all_devices, active_devices=active_devices)


@app.route('/interfaces/<device>/analysishub')
def analysishub(device=None):
    return render_template("analysishub.html", device=device)


@app.route('/help')
def help():
    return render_template("help.html")


if __name__ == '__main__':
    app.run(debug=True)
