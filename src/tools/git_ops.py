import os
from git import Repo, exc
from typing import Dict, Any
from src.tools.base import ToolInterface

class GitTool(ToolInterface):
    """
    Implements Git operations with policy-driven safeguards against 
    history modification and unauthorized pushes.
    """

    def execute(self, command: str, params: Dict[str, Any], constraints: Dict[str, Any]) -> Dict[str, Any]:
        repo_path = params.get("repo_path", ".")
        
        try:
            # Normalize path to ensure operations stay within intended directories
            abs_repo_path = os.path.abspath(repo_path)
            repo = Repo(abs_repo_path)
            
            # 1. Command: PUSH
            if command == "push":
                # Security Check: Enforce 'prevent_force_push' constraint
                is_force = params.get("force", False)
                if constraints.get("prevent_force_push", True) and is_force:
                    return {
                        "status": "denied", 
                        "message": "Policy Violation: Force push is prohibited by security policy."
                    }
                
                origin = repo.remotes.origin
                info = origin.push(force=is_force)
                return {"status": "success", "details": [str(i.summary) for i in info]}

            # 2. Command: COMMIT
            elif command == "commit":
                # Security Check: Enforce 'prevent_history_rewrite' constraint
                if constraints.get("prevent_history_rewrite", True) and params.get("amend", False):
                    return {
                        "status": "denied", 
                        "message": "Policy Violation: Amending commits (history rewrite) is prohibited."
                    }
                
                message = params.get("message", "Agent automated commit")
                new_commit = repo.index.commit(message)
                return {"status": "success", "sha": new_commit.hexsha}

            # 3. Command: PULL
            elif command == "pull":
                origin = repo.remotes.origin
                origin.pull()
                return {"status": "success", "current_sha": repo.head.commit.hexsha}

            else:
                return {"status": "error", "message": f"Unknown git command: {command}"}

        except exc.InvalidGitRepositoryError:
            return {"status": "error", "message": f"No valid git repository found at {repo_path}"}
        except exc.GitCommandError as e:
            return {"status": "error", "message": f"Git CLI error: {str(e)}"}
        except Exception as e:
            return {"status": "error", "message": f"Unexpected error: {str(e)}"}
