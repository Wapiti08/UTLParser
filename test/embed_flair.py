from flair.embeddings import FlairEmbeddings
from flair.embeddings import WordEmbeddings, FlairEmbeddings, StackedEmbeddings
from flair.data import Sentence

# init embedding
flair_embedding_forward = FlairEmbeddings('news-forward')

# stacked embeddings
stacked_embeddings = StackedEmbeddings([
                            WordEmbeddings('glove'),
                            FlairEmbeddings("news-forward"),
                            FlairEmbeddings("news-backward")
                        ])

# create a sentence
sentence = Sentence("The grass is green. ")

# embed words in sentence
flair_embedding_forward.embed(sentence)

# now check out the embedded tokens.
for token in sentence:
    print(token)
    print(token.embedding)
    print(token.embedding.shape)