# mathcamp-crypto

# SFU Math Camp on Cryptography

Welcome! This repository hosts the complete Python resources for a 5-day math camp on cryptography, developed for Grade 9-10 students at Simon Fraser University.

## Camp Philosophy

The camp's theme is an exploration of classical and modern cryptography. While the primary learning materials are in a printed notes booklet, these Python files provide an engaging, hands-on component. The goal is to demonstrate how programming can be a powerful tool for both creating and breaking codes.

We operate under the assumption that students have **no prior programming experience**. All code is provided, and the introductory notebook (`GetStartedPython.ipynb`) is designed to onboard students smoothly.

A significant portion of this code was inspired by Al Sweigart's outstanding book, [*Cracking Codes with Python*](https://nostarch.com/crackingcodes), which is highly recommended for anyone interested in this topic.

---

## File Descriptions

This repository is organized as follows:

-   `crypto.py`
    -   This is the central Python library for the camp. It contains functions for encrypting and decrypting messages using the ciphers taught in the notes booklet.

-   `GetStartedPython.ipynb`
    -   This is the main interactive lesson for the computer lab session. It guides students through importing the `crypto.py` library and using its functions to solve practical cryptography problems.

-   `Appendix-CryptoInPython.ipynb`
    -   This Jupyter Notebook serves as a digital appendix. It contains the complete source code from `crypto.py` in a readable format, which is referenced in the main notes booklet.

-   `MA.txt`
    -   A simple text file containing a longer encrypted message. This is used for a final capstone challenge where students must apply multiple techniques learned throughout the week to decipher it.

## How to Use These Materials

1.  **Prerequisites**: Ensure you have a Python environment capable of running Jupyter Notebooks (`.ipynb` files).
2.  **Start Here**: The `GetStartedPython.ipynb` notebook is the primary entry point for the interactive portion of the camp.
3.  **Core Logic**: The `crypto.py` file should be in the same directory as the notebooks so it can be imported correctly.

We hope these materials are useful for other educators and students interested in the exciting intersection of mathematics and computer science!