from setuptools import setup, Extension
import pybind11

module = Extension(
    'subtitle_engine',
    sources=['subtitle_engine.cpp'],
    include_dirs=[pybind11.get_include(), '.'],
    extra_compile_args=['-std=c++17', '-O3', '-fPIC'],
    language='c++',
)

setup(
    name='subtitle_engine',
    version='1.0',
    ext_modules=[module],
)
