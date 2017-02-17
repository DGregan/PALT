from flask import Flask
from flask import render_template
from flask import Markup
from PacketHandler import PacketHandler
app = Flask(__name__)


@app.route('/')
def index():
    return 'Index Page!'


@app.route('/about')
def about():
    # return 'About Page'
    my_p = PacketHandler()
    myvalue =my_p.get_all_devices()
    return render_template("about.html", daveisalad=myvalue)


@app.route('/interfaces')
@app.route('/interfaces/<device>/')
def interfaces(device=None):
    return render_template("interfaces.html", device=device)


if __name__ == '__main__':
    app.run(debug=True)
