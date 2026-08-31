# CCcam3 - entrada no menu de plugins (Enigma2)
# Menu > Plugins > CCcam3

from Plugins.Plugin import PluginDescriptor
from Screens.Screen import Screen
from Components.ActionMap import ActionMap
from Components.Label import Label
import os

INIT = "/etc/init.d/cccam3"
WEB_URL = "http://127.0.0.1:8080/web"


class CCcam3Menu(Screen):
    skin = """
    <screen position="center,center" size="620,300" title="CCcam3">
      <widget source="info" render="Label" position="20,20" size="580,50" font="Regular;22" halign="center"/>
      <widget source="status" render="Label" position="20,90" size="580,40" font="Regular;20" halign="center"/>
      <widget source="key_red" render="Label" position="10,240" size="190,45" font="Regular;20" halign="center" backgroundColor="red" foregroundColor="white"/>
      <widget source="key_green" render="Label" position="215,240" size="190,45" font="Regular;20" halign="center" backgroundColor="green" foregroundColor="white"/>
      <widget source="key_yellow" render="Label" position="420,240" size="190,45" font="Regular;20" halign="center" backgroundColor="yellow" foregroundColor="black"/>
    </screen>"""

    def __init__(self, session):
        Screen.__init__(self, session)
        self["info"] = Label("Servidor de cardsharing CCcam3")
        self["status"] = Label("")
        self["key_red"] = Label("Iniciar")
        self["key_green"] = Label("Parar")
        self["key_yellow"] = Label("Estado")
        self["actions"] = ActionMap(["ColorActions"], {
            "red": self.do_start,
            "green": self.do_stop,
            "yellow": self.do_status,
            "cancel": self.close,
        })
        self.onLayoutFinish.append(self.do_status)

    def do_status(self):
        out = ""
        if os.path.exists(INIT):
            out = os.popen(INIT + " status 2>&1").read().strip()
        self["status"].setText(out or "Servico nao encontrado")

    def do_start(self):
        if os.path.exists(INIT):
            os.system(INIT + " start")
        self.do_status()

    def do_stop(self):
        if os.path.exists(INIT):
            os.system(INIT + " stop")
        self.do_status()


def main(session, **kwargs):
    session.open(CCcam3Menu)


def Plugins(**kwargs):
    return [PluginDescriptor(
        name="CCcam3",
        description="Servidor de cardsharing CCcam3 (iniciar/parar/estado)",
        where=PluginDescriptor.WHERE_PLUGINMENU,
        fnc=main,
    )]
