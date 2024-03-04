# import spacy

# # Load the English language model
# nlp = spacy.load("en_core_web_lg")

# # Example text
# text = "reply[AAA]"

# # Process the text with spaCy
# doc = nlp(text)

# # Iterate over tokens in the processed document
# for token in doc:
#     # Get the lemma of the token
#     lemma = token.lemma_
#     print("Token:", token.text)
#     print("Lemma:", lemma)



import spacy
from spacy.tokenizer import Tokenizer
from spacy.lang.en import English

# Load just the English tokenizer
nlp = English()

# Create a tokenizer instance
tokenizer = Tokenizer(nlp.vocab)

# Example text
text = "reply[AAA]"

# Tokenize the text
tokens = tokenizer(text)

# Get the lemma of the first token
lemma = tokens[0].lemma_
print("Lemma:", lemma)

import re

# Example text
text = "This is a [test] (string) with [multiple] (parts) inside."

# Remove parts within square brackets
text_without_square_brackets = re.sub(r'\[.*?\]', '', text)

# Remove parts within parentheses
text_without_parentheses = re.sub(r'\(.*?\)', '', text)

print("Text without square brackets:", text_without_square_brackets)
print("Text without parentheses:", text_without_parentheses)