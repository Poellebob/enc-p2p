class ConsoleWindow:

    # det var meningen at der skulle være et UI her.
    # men det her virker fin

    def display_message(self, message: str):
        print(message)

    def display_received_message(self, message: str):
        print(f"\nReceived: {message}\nEnter message to send: ", end="")

    def get_input(self, prompt: str) -> str:
        return input(prompt)
