from setuptools import setup, Extension
import pybind11
import numpy

# KissFFT kaynak dosyaları
kissfft_sources = [
    'kissfft/kiss_fft.c',
    'kissfft/tools/kiss_fftr.c'
]

# C++ Kaynak dosyası
viz_source = ['viz_engine.cpp']

# Tüm kaynak dosyaları
sources = viz_source + kissfft_sources

# KissFFT için include dizinleri
include_dirs = [
    pybind11.get_include(),
    numpy.get_include(),
    './kissfft',  # KissFFT ana dizini
    '/usr/include/libprojectM',  # system projectM headers
]

# Modül tanımı
module = Extension(
    'viz_engine', 
    sources=sources,
    include_dirs=include_dirs,
    define_macros=[('VIZ_WITH_PROJECTM', '1')],
    libraries=['projectM', 'stdc++'],
    extra_compile_args=['-std=c++17', '-fPIC'],
    language='c++'
)

setup(
    name='viz_engine',
    version='1.1',
    ext_modules=[module],
)
