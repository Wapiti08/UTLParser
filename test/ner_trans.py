from flair.datasets import CONLL_03
from flair.embeddings import TransformerWordEmbeddings
from flair.models import SequenceTagger
from flair.trainers import ModelTrainer

# get the corpus
corpus = CONLL_03()

# what label to predict
label_type = 'ner'

# make the label dictionary from the corpus ---- can be custom corpus
label_dict = corpus.make_label_dictionary(label_type = label_type, add_unk=False)
print(label_dict)

# initialize fine-tuneable transformer embeddings WITH document context
embeddings = TransformerWordEmbeddings(model='xml-roberta-large',
                                       layers='-1',
                                       subtoken_pooling='first',
                                       fine_tune=True,
                                       use_context=True)

# initialize bare-bones sequence tagger
tagger = SequenceTagger(hidden_size=256,
                        embeddings=embeddings,
                        tag_dictionary=label_dict,
                        tag_type='ner',
                        use_crf=False,
                        use_rnn=False,
                        reproject_embeddings=False,
                        )

# initialize trainer
trainer = ModelTrainer(tagger, corpus)

# run fine-tuning
trainer.fine_tune('resources/taggers/sota-ner-flert',
                  learning_rate=5.0e-6,
                  mini_batch_size=4,
                  mini_batch_chunk_size=1,  # remove this parameter to speed up computation if you have a big GPU
                  )
