import os
import sys

# Make the connector modules under src/ importable as top-level modules,
# matching how connector.py imports them at runtime (WORKDIR is src/).
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))
