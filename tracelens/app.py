"""Console entry point: launch the TraceLens terminal UI."""

from tracelens.tui.app import TraceLensApp


def main() -> None:
    """Run the TraceLens TUI (path entry → analyze → evidence review)."""
    TraceLensApp().run()


if __name__ == "__main__":
    main()
