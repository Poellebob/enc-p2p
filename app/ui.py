class ConsoleWindow:
    """Handles console input and output for the chat application."""

    def display_message(self, message: str):
        """Displays a generic message to the console."""
        print(message)

    def display_received_message(self, message: str):
        """Formats and displays a received message."""
        print(f"\nReceived: {message}\nEnter message to send: ", end="")

    def get_input(self, prompt: str) -> str:
        """Gets input from the user with a given prompt."""
        return input(prompt)
