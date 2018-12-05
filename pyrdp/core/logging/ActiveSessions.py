from typing import Dict


class ActiveSessions:
    """
    Class to keep a list of active sessions across the MITM program.
    """

    sessions: Dict = {}

    @staticmethod
    def add(sessionId: str, mitmServer):
        ActiveSessions.sessions[sessionId] = mitmServer

    @staticmethod
    def remove(sessionId: str):
        ActiveSessions.sessions.pop(sessionId)

    @staticmethod
    def get(sessionId: str):
        return ActiveSessions.sessions[sessionId]
