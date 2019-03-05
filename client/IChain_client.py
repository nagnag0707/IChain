# coding utf-8
# python 3.6
# Data_Client for IChain
# J413 

import hashlib
import json
import urllib
import random
import sys

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from base64 import b64decode, b64encode


from time import time
from urllib.parse import urlparse
from uuid import uuid4

import requests
from flask import Flask, jsonify, request, render_template, redirect, url_for
from flask_login import LoginManager, logout_user

class IChain_Client:

    def __init__(self, secret_key, public_key, port):
        self.API_URL = 'http://127.0.0.1:5000'
        self.myAccept_id = self.register_node("000.000.000.000",port)
        self.myNodes = self.get_node()
        self.myIP = self.get_global_add(self.myAccept_id)
        self.myPort = port
        
        self.mySecret = b64encode(secret_key).decode('utf-8')
        self.myPublic = b64encode(public_key).decode('utf-8')
        
        self.chain = []
        self.transaction = []
        
        # genesis blockを生成
        self.register_block(proof = 1000, pre_hash = 1)
        # チェーンをネットワークから更新
        self.consensus()
        print('---------------------------------------')
        print('IChain_Client Started! ' + self.myIP)    
        print('Your Accept_id is ' + self.myAccept_id)
        print('')
        print('Secret key: ' + str(self.mySecret))
        print('Public key: ' + str(self.myPublic))
        print(type(self.mySecret))
        print('---------------------------------------')
        
        self.node_add_request()
        
    # ------------------------------------------------------------------------ #
    # function for nodes 
    
    # 自らのグローバルアドレスを取得
    def get_global_add(self, accept_id):
        url = self.API_URL + '/get_myNode'
        headers = {"content-type":"application/json; charset=utf-8"}
        
        data= {
            "accept_id":accept_id
        }
        
        #POST
        response = requests.post(url, data=json.dumps(data),headers = headers).json()
        return response[-1]['IP']
    
    # ノード一覧を取得    
    def get_node(self):
        url = self.API_URL + '/getNode'
        nodes = []
        
        headers = {"content-type":"application/json; charset=utf-8"}
        
        #POST
        response = requests.get(url).json()
        
        for i in response['nodes']:
            data = {'ip':i['ip'], 'port':i['port']}
            nodes.append(data)
        
        return nodes
        
    # ノード参加リクエスト - ノードサーバ
    def register_node(self, Add, Port):
        url = self.API_URL + '/register_node'

        
        headers = {"content-type":"application/json; charset=utf-8"}
        
        data= {
            "ip":Add,
            "port":Port
        }
        
        #POST
        response = requests.post(url, data=json.dumps(data),headers = headers)
        if response.status_code == 201:
            response = response.json()
            return response['accept_id']
        else:
            print('ERROR! 既に同一IPからの登録があります。ノード削除依頼をしますか？ y/n')
            flag = input()
            if flag == 'y':
                print('ACCEPT_IDを入力してください。')
                accept_id = input()
                url = self.API_URL + '/delete_node'
                headers = {"content-type":"application/json; charset=utf-8"}
        
                data= {
                    "accept_id":accept_id
                }
        
                #POST
                response = requests.post(url, data=json.dumps(data),headers = headers)
                if response.status_code == 201:
                    print('削除が成功しました。システムを再起動してください。')
                    sys.exit()
                else:
                    print('削除に失敗しました。ACCEPT_IDを確認し再入力を行うか、管理者にノード削除依頼を申請してください。')
            elif flag != 'y':
                print('ノードとして参加するには、既存のノード情報を削除する必要があります。')
                print('システムを終了します。')
                sys.exit()
    
    # ノード追加要求 - 各ノード
    def node_add_request(self):
        self.check_nodes()
                    
    def check_nodes(self):
        Nodes = self.myNodes
        for i in Nodes:
            if i['ip'] != self.myIP or i['port'] != self.myPort:
                # ノードに対して自らのIP情報の登録要求
                url = 'http://' + i['ip'] + ':' + i['port'] + '/check_node'
                headers = {"content-type":"application/json; charset=utf-8"}
        
                try:
                    response = requests.get(url)
                except:
                    self.myNodes.remove(i)
                    self.check_nodes()   
    
    # ------------------------------------------------------------------------ #
    # function for blockchain 
    
    # 最後のブロックを返す
    @property
    def last_block(self):
        return self.chain[-1]
        
    # ブロック生成
    def register_block(self, proof, pre_hash = None):
        
        # --- BLOCKの構成要素 ---
        # index:順に生成される番号
        # timestamp:生成時刻
        # transactions:チェーンに追加するトランザクション
        # proof:前のブロックの解
        # pre_hash:一つ前のハッシュ値
        
        block = {
            'index':len(self.chain) + 1,
            'timestamp':time(),
            'transactions':self.transaction,
            'proof':proof,
            'pre_hash':pre_hash or self.hash_block(self.chain[-1])
        }
        
        # トランザクションを空に
        self.transaction = []
        
        # ブロックをチェーンに追加
        self.chain.append(block)
        
        return block
    
    # トランザクション生成
    def register_transaction(self, recipient, signature):
        
        # Sender    :自身の公開鍵
        # Recpient  :送信先
        # Signature :ハッシュ化され、自身の秘密鍵によって署名されたデータ
        
        Sender = self.myPublic
        Recpient = recipient
        Signature = self.sign_rsa(signature)
        
        transaction = ({
            'sender': Sender,
            'recipient': Recpient,
            'signature': Signature,
        })        
        
        self.transaction.append(transaction)
        
        return transaction
        
    # デジタル署名
    def sign_rsa(self, data):
        
        # 変換元データをハッシュ化しバイト形式に変換
        b_data = self.hash(data).encode()
        
        # 秘密鍵をb64からデコードしインポート
        try:
            rsakey = RSA.importKey(b64decode(self.mySecret), passphrase = None)
        except ValueError as e:
            print('rsaError!' + e)
        
        # 署名
        h = SHA256.new(b_data)
        signature = PKCS1_v1_5.new(rsakey).sign(h)
         
        #print(b_data.decode())
        #print(self.hash(data))
        
        # b64形式でエンコードしたデータを返す
        return b64encode(signature).decode('utf-8')
        
    # 署名検証
    def verify_sha(self, public_key, sign_data, data):
        
        data_hash = self.hash(data).encode()
        
        try:
            sha = SHA256.new(data_hash)
            key = RSA.importKey(public_key)
            result=PKCS1_v1_5.new(key).verify(sha, sign_data)
            
            return result
        except (ValueError, TypeError):
            return result
            
    # データのハッシュ化
    def hash(self, data):
        return hashlib.sha256(data.encode()).hexdigest()
    
    # ブロックのハッシュ化
    def hash_block(self, data):
        block_data = json.dumps(data, sort_keys=True).encode()
        return hashlib.sha256(block_data).hexdigest()
        
    # コンセンサス
    def consensus(self):
        # 他ノードから最長のノードを取得し整合性をとる
        
        myChain = self.chain
        newChain = []
        
        myLength = len(self.chain)
        
        
        # 全ノードに問い合わせ
        for i in self.myNodes:
            if i['ip'] != self.myIP or i['port'] != self.myPort:
                # ノードに対して自らのIP情報の登録要求
                url = 'http://' + i['ip'] + ':' + i['port'] + '/get_chain'
                headers = {"content-type":"application/json; charset=utf-8"}
                
                response = requests.get(url)
                
                if response.status_code == 200:
                    chain = response.json()['chain']
                    length = response.json()['length']
                    
                    if length > myLength and self.verification_chain(chain):
                        myLength = length
                        newChain = chain
        
        if newChain != []:
            self.chain = newChain
            return True
        
        return False
        
    # チェーンの整合性を確認                    
    def verification_chain(self, chain):
        # チェーンの検証
        # １つ前のブロックとハッシュ値を比較
        # POWが正しいか確認
        
        last_block = chain[0]
        index = 1
        
        while index < len(chain):
            block = chain[index]
            last_hash = self.hash_block(last_block)
            
            if block['pre_hash'] != last_hash:
                return False
                
            last_block = block
            index += 1
        
        return True
   
    # proofの整合性を確認 - 難易度4桁 
    @staticmethod
    def verification_proof(cur_proof, proof):
        
        ver_proof = f'{cur_proof}{proof}'.encode()
        proof_hash = hashlib.sha256(ver_proof).hexdigest()

        return proof_hash[:4] == "0000"
        
    # proof of work
    def proof_of_work(self, last_proof):
        # ハッシュ値の開始n桁が0となる解を計算する。
        
        proof = 0
        
        while self.verification_proof(last_proof, proof) is False:
            proof += 1
        
        return proof 
                
    # チェーンのトランザクションからデータを参照して返す    
    def search_transaction(self, recipient, data, number, number_sign):
    #def search_transaction(self):
        res = 'FAILED!|| ' + data + ' is False!'
        transactions = []
        

        # 正当なチェーンに更新
        self.consensus()

        # チェーンを辿りトランザクションを変数に格納
        for i in self.chain:
            for j in i['transactions']:
                transactions.append(j)
        
        # トランザクションリストから受信者とハッシュデータが等しいものを検索
        for i in transactions:
            if i['recipient'] == recipient:
                #　データをデコード
                sen = b64decode(i['sender'])
                rec = b64decode(i['recipient'])
                sig = b64decode(i['signature'])
                snu = b64decode(number_sign)
                
                #print('sender:' + str(sen))
                #print('recipient:' + str(rec))
                
                # 証明者の署名によるデータであるとの証明
                if self.verify_sha(sen, sig, data):
                    # 提示者が被証明者であることの証明
                    if self.verify_sha(rec, snu, number):
                        res = 'SUCCESS|| ' + data + ' is True!'
        return res
        
try:     
    PUBLIC_KEY = 'public.pem'
    PRIVATE_KEY = 'private.pem'
    
    print('公開鍵と秘密鍵をディレクトリ直下に配置してください。')
    print('公開鍵: publc.pem / 秘密鍵: private.pem')
    
    f = open(PUBLIC_KEY,'rb')
    public_key = f.read()
    
    f = open(PRIVATE_KEY,'rb')
    secret_key = f.read()
    
    
    print('稼働するポート番号を入力してください。')
    port = input()
    if not (public_key is None and secret_key is None):
        # flask有効化
        app = Flask(__name__)
        # IChainクラス作成
        client = IChain_Client(secret_key, public_key, port)
        
        # flaskログインマネージャー
        login_manager = LoginManager()
        login_manager.init_app(app)
    else:
        print('システムの起動には公開鍵と秘密鍵が必要です。')
        print('システムを終了します。')
        sys.exit()
        
    # ------------------------------------------------------------------------ #
    # WEB PAGE REQUESTS
        
    @app.route('/', methods=['GET'])
    def form():
        return render_template('login.html')

    @app.route('/login', methods=['POST'])
    def login():
        return redirect(url_for('dashboard'))
    
    
    
    
    # ------------------------------------------------------------------------ #
    # API REQUESTS
    # 自分のチェーン情報を返す - 認証不要
    @app.route('/get_chain', methods=['GET'])
    def my_chain():
        
        client.check_nodes()
        # チェーンを最新の状態に更新 - todo
        
        response = {
            'chain': client.chain,
            'length': len(client.chain),
        }
        return jsonify(response), 200
    
    # 自分のチェーン情報を返す - 認証不要
    @app.route('/get_Nchain', methods=['GET'])
    def my_nchain():
        
        client.check_nodes()
        # チェーンを最新の状態に更新 - todo
        res = client.consensus()
        
        if res == True:
            message = 'チェーンが更新されました。'
        if res == False:
            message = 'チェーンの更新はありませんでした。'
        
        response = {
            'chain': client.chain,
            'length': len(client.chain),
            'message':message
        }
        return jsonify(response), 200
        
    
    # 自身のトランザクション情報を返す - 認証不要
    @app.route('/get_transaction', methods=['GET'])
    def my_transaction():
        response = {
            'transaction': client.transaction,
            'length': len(client.transaction),
        }
        return jsonify(response), 200
    
    # ノード応答確認  - 認証不要
    @app.route('/check_node', methods=['GET'])
    def res_node():
        response = {
            'message':'Hi! myNode!'
        }
        client.myNodes = client.get_node()
        return jsonify(response), 200
    
    # ノード追加リクエスト - 認証不要
    @app.route('/add_node', methods=['POST'])
    def add_node():
        values = request.get_json()
    
        ip = values.get('ip')
        port = values.get('port')
        
        new_node = {'ip':ip, 'port':port}
        client.myNodes.append(new_node)
        
        print('ADD NEW NODE!:' + ip + ':' + port)
        
        response = "success"
        return jsonify(response), 201
    
    # トランザクションを生成し追加 - 要認証[accept_id]
    @app.route('/register_transaction', methods=['POST'])
    def register_transaction():
        values = request.get_json()
    
        accept_id = values.get('accept_id')
        if accept_id is None:
            return "Error: Accept_idを入力してください。", 400
        if accept_id != client.myAccept_id:
            return "Error: 不正なAccept_idが入力されました。", 400
    
        required = ['recipient', 'signature']
        if not all(k in values for k in required):
            return 'Error:トランザクションデータ形式が不正です。', 400
    
    
        index = client.register_transaction(values['recipient'], values['signature'])
        response = {'message': f'Transaction will be added to Block {index}'}
        return jsonify(response), 201
    
    # マイニングを行いチェーンを返す - 要認証[accept_id]
    @app.route('/mine', methods=['POST'])
    def mine():
        
        values = request.get_json()
    
        accept_id = values.get('accept_id')
        if accept_id is None:
            return "Error: Accept_idを入力してください。", 400
        if accept_id != client.myAccept_id:
            return "Error: 不正なAccept_idが入力されました。", 400
        
        # チェーンを最新の状態に更新
        
        client.consensus()
        
        # 最後のブロックを取得しマイニングを行う
        last_block = client.last_block
        proof = client.proof_of_work(last_block)
        
        previous_hash = client.hash_block(last_block)
        block = client.register_block(proof, previous_hash)
        
        response = {
            'message': "New Block Forged",
            'blcok':block
        }
        return jsonify(response), 200
    
    # 証明リクエスト送信 - 要認証[accept_id]
    @app.route('/put_verify', methods=['POST'])
    def put_verify():
        
        values = request.get_json()
    
        accept_id = values.get('accept_id')
        if accept_id is None:
            return "Error: Accept_idを入力してください。", 400
        if accept_id != client.myAccept_id:
            return "Error: 不正なAccept_idが入力されました。", 400    

        required = ['ip', 'port', 'data']
        if not all(k in values for k in required):
            return 'Error:データ形式が不正です。{ip:str, port:str, data:str}', 400
        
        # 1-100000の間で乱数を作成
        num = str(random.randint(1,100000))
        num_sign = client.sign_rsa(num)
        print(str(num_sign))
        client.myNodes = client.get_node()
        client.check_nodes()
        
        enable_node = False
        
        for i in client.myNodes:
            if values.get('ip') == i['ip'] and values.get('port') == i['port']:
                enable_node = True
        
        if enable_node == False:
            return "Error: 宛先ノードが有効か確認してください。", 400
        
        
        # 疎通確認
        url = 'http://' + values.get('ip') + ':' + values.get('port') + '/check_node'
        headers = {"content-type":"application/json; charset=utf-8"}
        
        response = requests.get(url)     
        
        if response.status_code == 200:
            url = 'http://' + values.get('ip') + ':' + values.get('port') + '/get_verify'
            headers = {"content-type":"application/json; charset=utf-8"}
            
            data = {
                "recipient":client.myPublic,
                "data":values.get('data'),
                "num":num,
                "num_sign":num_sign
            }
            
            response = requests.post(url, data=json.dumps(data),headers = headers)
            
            if response.status_code == 201:
                response = response.json()
                return jsonify(response), 200
        
    
        return "Error: 処理中に不正な処理が実行されました。再試行してください。", 400
        
        
            
 
     # 証明リクエスト受信 - 認証不要
    @app.route('/get_verify', methods=['POST'])
    def get_verify():
        
        values = request.get_json()
    
        required = ['recipient', 'data', 'num', 'num_sign']
        if not all(k in values for k in required):
            return 'Error:データ形式が不正です。{ip:str, port:str, data:str}', 400
        
        recipient = values.get('recipient')
        data = values.get('data')
        num = values.get('num')
        num_sign = values.get('num_sign')
        
        
        verify =  client.search_transaction(recipient, data, num, num_sign)
        
        response = {
            'message':verify
        }
        
        return jsonify(response), 201
        
    if __name__ == '__main__':
        
        from argparse import ArgumentParser
    
        parser = ArgumentParser()
        parser.add_argument('-p', '--port', default=5001, type=int, help='port to listen on')
        args = parser.parse_args()
        port = args.port
    
        app.run(host='0.0.0.0', port=port, threaded=True)

except KeyboardInterrupt:
    print("Closing")
    print(client.myIP)