#!/usr/bin/env python3
"""
Test file for demonstrating suppression and sanitizer detection
"""

import html
import re
from flask import request

def test_suppressed_eval():
    """This should NOT be reported due to suppression"""
    user_input = request.args.get('data')
    # nosast: eval
    result = eval(user_input)
    return result

def test_sanitized_xss():
    """This should have LOW confidence due to sanitizer"""
    user_input = request.args.get('html')
    # Sanitize the input
    safe_input = html.escape(user_input)
    # This should still be flagged but with low confidence
    return f"<div>{safe_input}</div>"

def test_real_vulnerability():
    """This should be reported with HIGH confidence"""
    user_input = request.args.get('code')
    # No suppression, no sanitizer - real vulnerability!
    return eval(user_input)

def test_sql_injection_sanitized():
    """SQL injection with parameterized query (sanitized)"""
    import sqlite3
    user_id = request.args.get('id')

    # Safe parameterized query (should have lower confidence)
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    # Using parameterized query is safe
    cursor.execute("SELECT * FROM users WHERE id = ?", (int(user_id),))

    return cursor.fetchall()

def test_sql_injection_vulnerable():
    """SQL injection without sanitization"""
    import sqlite3
    user_id = request.args.get('id')

    # Vulnerable string concatenation
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    # This is vulnerable!
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

    return cursor.fetchall()

def test_multiple_suppressions():
    """Test multiple suppression patterns"""
    data = request.form.get('data')

    # nosast: all
    exec(data)

    # Specific suppression
    # nosast: os.system
    import os
    os.system(data)

if __name__ == "__main__":
    print("Suppression and sanitizer test file")
