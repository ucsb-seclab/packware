import pykka
import ujson as json
import training

'''
threading module
'''


class ConsumerActor(pykka.ThreadingActor):
    '''
    Implement a thread as Actor.
    When instantiated
    ConsumerActor().start(df, params, model_name, divide_fun)
    the class stores the parameters needed for the experiment.
    Everytime a message is received the actor starts running the experiment.
    Message content is ignored.
    '''
    def __init__(self, df, indices, params, model_name, divide_fun, n_jobs, res_dir, compute_conf_score):
        '''
        :param df: tuple of pandas dataframe
        :param indices: store indices for four sets of packed_benign, unpacked_benign, packed_malicious, unpacked_malicious
        :param params: tuple of ratio of packed benign, ratio of packed malicious, experiment round
        :param model_name: name of the sklearn model used
        :param divide_fun: function used to divide the dataset using ratio_ben, ratio_mal
        :rtype: future that the main thread polls to get the data to store on db
        '''
        super().__init__()
        self.df = df # tuple of pandas dataframe
        self.indices = indices
        self.ratio_ben, self.ratio_mal, self.round = params
        self.model_name = model_name
        self.divide_fun = divide_fun
        self.n_jobs = n_jobs
        self.res_dir = res_dir
        self.compute_conf_score = compute_conf_score
        id = '{}-{}-{}'.format(self.ratio_ben, self.ratio_mal, self.round)
        print('Created Consumer, ID:', id)

    def on_receive(self, message):
        '''
        mailbox for messages
        Content ignored, starts the experiment
        :param message: dictionary, always a dictionary
        :rtype future
        '''
        try:
            return self.run_experiment()
        except Exception as e:
            return ((self.ratio_ben, self.ratio_mal, self.round), e)

    def run_experiment(self):
        '''
        Run training.py experiment with the parameters got at instantiation
        :rtype: (string, (params for query))
        :return: tuple to be used as database query
        '''
        res = training.experiment(self.model_name, self.df, self.indices, (self.ratio_ben, self.ratio_mal), self.round, self.divide_fun, self.n_jobs, self.res_dir, self.compute_conf_score)

        results = json.dumps(res['results'])

        if self.round == 0:
            conf = json.dumps(res['confidence'])
            features = json.dumps(res['importances'][0])
            weights = json.dumps(res['importances'][1])

            query = ('''INSERT INTO results VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (self.ratio_mal, self.ratio_ben, self.round, features, weights, results, conf))
        else:
            query = ('''INSERT INTO results VALUES (?, ?, ?, NULL, NULL, ?, NULL)''',
                (self.ratio_mal, self.ratio_ben, self.round, results))

        id = '{}-{}-{}'.format(self.ratio_ben, self.ratio_mal, self.round)
        print('ID:', id, 'has finished')
        return id, query



#'''CREATE TABLE results
          # (ratio_mal real, ratio_ben real, round integer, features text, weights text, results text, confidence text)'''
