#!/usr/bin/env python3
import ast
import sys

try:
    with open('main.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Validar sintaxis
    ast.parse(content)
    print("✅ Sintaxis Python válida")
    
except SyntaxError as e:
    print(f"❌ Error de sintaxis: {e}")
    print(f"Línea: {e.lineno}")
    print(f"Columna: {e.offset}")
    print(f"Texto: {e.text}")
    
except Exception as e:
    print(f"❌ Error al leer archivo: {e}")
