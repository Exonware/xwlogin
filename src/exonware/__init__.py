"""
exonware package - Enterprise-grade Python framework ecosystem
Company: eXonware.com
Author: eXonware Backend Team
Email: connect@exonware.com
This is a namespace package allowing multiple exonware subpackages
to coexist (xwsystem, xwnode, xwdata, xwauth, xwlogin, etc.)
"""

__path__ = __import__("pkgutil").extend_path(__path__, __name__)
