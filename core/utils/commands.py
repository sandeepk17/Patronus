from core.sast.golang import GoLang
from core.sast.nodejs import NodeJs
from core.sast.java import Java


class Command():
    """
    """
    def __init__(self):
        """
        """
        self.go = GoLang()
        self.npm = NodeJs()
        self.java = Java()

    def run_command(self, cmd_name: str, repo:str):
        """
        """
        if cmd_name is "spotbugs":
            return self.java.project_build(repo)
        elif cmd_name is "gosec":
            return self.go.gosec(repo)
        elif cmd_name is "npm_audit":
            return self.npm.npm_audit(repo)