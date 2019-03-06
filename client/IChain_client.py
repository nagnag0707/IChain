# coding utf-8
# python 3.6
# Data_Client for IChain
# J413 

import hashlib
import json
import urllib
import random
import sys
import cgi

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from base64 import b64decode, b64encode


from time import time
from urllib.parse import urlparse
from uuid import uuid4

import requests
from flask import Flask, jsonify, request, render_template, redirect, url_for
from flask_login import logout_user, UserMixin, login_required, login_user, LoginManager

# Viewを参照するか
View_log = True


class User(UserMixin):
    def get_id(self):
        return 1


class IChain_Client:

    def __init__(self, secret_key, public_key, port, name):
        # ログ表示設定
        self.View_log = True
        
        self.CLIENT_NAME = name
        self.API_URL = 'http://3.17.156.77:5000'
        self.myAccept_id = self.register_node("000.000.000.000",port)
        self.myNodes = self.get_node()
        self.myIP = self.get_global_add(self.myAccept_id)
        self.myPort = port
        self.myURL = 'http://' + self.myIP + ':' + self.myPort
        
        self.mySecret = b64encode(secret_key).decode('utf-8')
        self.myPublic = b64encode(public_key).decode('utf-8')
        
        self.chain = []
        self.transaction = []
        
        # genesis blockを生成
        self.register_block(proof = 1000, pre_hash = 1)
        # チェーンをネットワークから更新
        self.consensus()
        print('---------------------------------------')
        print('IChain_Client Started! ' + self.myIP + ':' + self.myPort)
        print('Your Client Name is ' + self.CLIENT_NAME)
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
        
        if self.View_log:
            print('ノードサーバーからこのサーバーのIPアドレスを参照します。')
            print('request to ' + str(url))
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
            
        if self.View_log:
            print('ノードサーバーからノード一覧を参照します。')
            print('request to ' + str(url) + ' nodes length:' + str(len(nodes)))
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
            
            if self.View_log:
                print('ノード参加リクエストが承認されました。 Status_code:201')
            
            
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
                    if self.View_log:
                        print('ノード確認応答リクエスト')
                        print('request@' + str(i['ip']) + ':' + str(i['port']))
                except:
                    if self.View_log:
                        print('ノードが応答しませんでした。ノードリストから除外します')
                        print('request@' + str(i['ip']) + ':' + str(i['port']))
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
        
        if self.View_log:
            print('add transaction!')
            print('Sender:' + str(self.myPublic))
            print('Recpient:' + str(recipient))
            print('Signature:' + str(signature))
        
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
        res =  b64encode(signature).decode('utf-8')
        
        if self.View_log:
            print('署名リクエストにより以下のデータを秘密鍵によって署名しました。')
            print(str(data) + ' ：署名前')
            print(str(res) + ' :署名後')
        
        return res
    # 署名検証
    def verify_sha(self, public_key, sign_data, data):
        
        data_hash = self.hash(data).encode()
        
        try:
            sha = SHA256.new(data_hash)
            key = RSA.importKey(public_key)
            result=PKCS1_v1_5.new(key).verify(sha, sign_data)
            
            if self.View_log:
                print('sign_data == data is' + str(result))
            
            return result
        except (ValueError, TypeError):
            return result
            
    # データのハッシュ化
    def hash(self, data):
        if self.View_log:
            print(str(data) + '　をハッシュ化します。')
        return hashlib.sha256(data.encode()).hexdigest()
    
    # ブロックのハッシュ化
    def hash_block(self, data):
        if self.View_log:
            print('ブロックをハッシュ化します。')
        
        block_data = json.dumps(data, sort_keys=True).encode()
        return hashlib.sha256(block_data).hexdigest()
        
    # コンセンサス
    def consensus(self):
        # 他ノードから最長のノードを取得し整合性をとる
        
        myChain = self.chain
        newChain = []
        
        myLength = len(self.chain)
        
        if self.View_log:
            print('コンセンサスアルゴリズムを実行します。')
        
        
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
            
            if self.View_log:
                print('ノードが更新されました。')
            
            self.chain = newChain
            return True
            
        if self.View_log:
            print('ノードは更新されませんでした。')        
        return False
        
    # チェーンの整合性を確認                    
    def verification_chain(self, chain):
        # チェーンの検証
        # １つ前のブロックとハッシュ値を比較
        # POWが正しいか確認
        
        last_block = chain[0]
        index = 1
        
        if self.View_log:
            print('自らのチェーンの整合性を確認します。')
        
        while index < len(chain):
            block = chain[index]
            last_hash = self.hash_block(last_block)
            
            if block['pre_hash'] != last_hash:
                if self.View_log:
                    print('チェーンに不正が見つかりました。完全性を維持するため他ノードからチェーンを参照します。')
                return False
                
            last_block = block
            index += 1
        
        if self.View_log:
            print('チェーンに異常はありませんでした。')
        
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
        
        if self.View_log:
            print('チェーンの解を算出します。')
        proof = 0
        
        while self.verification_proof(last_proof, proof) is False:
            proof += 1
        
        if self.View_log:
            print('解が算出されました。 ' + str(proof))
        return proof 
                
    # チェーンのトランザクションからデータを参照して返す    
    def search_transaction(self, recipient, data, number, number_sign):
    #def search_transaction(self):
        res = 'FAILED! ' + self.CLIENT_NAME + ' は ' + data + ' を承認しませんでした!'
        transactions = []
        

        # 正当なチェーンに更新
        self.consensus()

        # チェーンを辿りトランザクションを変数に格納
        for i in self.chain:
            for j in i['transactions']:
                transactions.append(j)
                
        if self.View_log:
            print('全' + str(len(transactions)) + 'トランザクションから情報を検索します。')
        
        # トランザクションリストから受信者とハッシュデータが等しいものを検索
        for i in transactions:
            if i['recipient'] == recipient:
                # for j in self.whitelist:
                    # if j['public_key'] == i['sender']:
                #　データをデコード
                sen = b64decode(i['sender'])
                rec = b64decode(i['recipient'])
                sig = b64decode(i['signature'])
                snu = b64decode(number_sign)
                
                #print('sender:' + str(sen))
                #print('recipient:' + str(rec))
                
                # 証明者の署名によるデータであるとの証明
                if self.verify_sha(sen, sig, data):
                    if self.View_log:
                        print('送信者による署名を確認しました。')
                    # 提示者が被証明者であることの証明
                    if self.verify_sha(rec, snu, number):
                        if self.View_log:
                            print('受信者本人のリクエストであると確認しました。')
                            print('SUCCESS!')
                        
                        res = 'SUCCESS! ' + self.CLIENT_NAME + ' は ' + data + ' を承認しました!'
        return res
        
try:
    View_log = True
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
    
    print('組織/個人名を入力して下さい。(任意)')
    name = input()
    if name is None:
        name = 'test user@' + str(uuid4()).replace('-', '')
    else:
        name = name + '@' + str(uuid4()).replace('-', '')
        
    if not (public_key is None and secret_key is None):
        # flask有効化
        app = Flask(__name__)
        # IChainクラス作成
        client = IChain_Client(secret_key, public_key, port, name)
        app.secret_key = client.myAccept_id
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
    def hello():
        
        if View_log:
            print('Called top page! send redirect to /login!')
        
        name = client.CLIENT_NAME
        return render_template('login.html', title='Login to IChain', name = name)
    
        
    @app.route('/login', methods=['GET'])
    def form():
        
        if View_log:
            print('User is watching login page!')
        
        name = client.CLIENT_NAME
        return render_template('login.html', title='Login to IChain', name = name)
    
    
    @app.route('/login', methods=['POST'])
    def login():
        accept_id = request.form['accept_id']
        if View_log:
            print('login request!:' + accept_id)
        if accept_id == client.myAccept_id:
            user = User()
            login_user(user)
            
            if View_log:
                print('login is success! create user and redirect to /dashboard!')
            return redirect(url_for('dashboard'))
        else:
            if View_log:
                print('login is failed! show error log!')
            return render_template('message.html', title = 'failed! to login!', message = "Error! 正しいaccept_idを入力して下さい。")
    
    # @login_required - 要ログイン
    @app.route('/dashboard', methods=['GET'])
    @login_required
    def dashboard():
        myID = client.myAccept_id
        name = client.CLIENT_NAME
        
        if View_log:
            print('User is watching dashboard!')
        
        return render_template('dashboard.html', title = 'IChain DashBoard', accept_id = myID, name = name)
    
    # @login_required - 要ログイン
    @app.route('/Identification', methods=['POST'])
    @login_required
    def Identification():
        accept_id = client.myAccept_id
        ip = request.form['ip']
        port = request.form['port']
        data = request.form['data']
        
        url = client.myURL + '/put_verify'
        headers = {"content-type":"application/json; charset=utf-8"}
        
        data= {
            "accept_id":accept_id,
            "ip":str(ip),
            "port":str(port),
            "data":str(data)
        }
        
        if View_log:
            print('User is requested Identification!')
            print('IP:' + str(ip) + ' PORT:' + str(port) + ' data:' + str(data))
        
        #POST
        response = requests.post(url, data=json.dumps(data),headers = headers)
        if response.status_code == 200:
            
            message = response.json()['message']
            if View_log:
                print('node connect is success!')
                print('result:' + str(message))
        else:
            message = 'Error! 宛先ノードに到達できませんでした。'
        
        return render_template('message.html', title = 'result by Identification', message = message)
    
    # トランザクション生成リクエスト    
    # @login_required - 要ログイン
    @app.route('/Add_transaction', methods=['POST'])
    @login_required
    def add_transaction():
        message = 'error! transcation is not added!'
        accept_id = client.myAccept_id
        recipient = request.form['recipient']
        signature = request.form['signature']
        
        url = client.myURL + '/register_transaction'
        headers = {"content-type":"application/json; charset=utf-8"}
        
        data= {
            "accept_id":accept_id,
            "recipient":str(recipient),
            "signature":str(signature)
        }
        if View_log:
            print('User is requested new transcation!')
            print('recipient:' + str(recipient))
            print('signature:' + str(signature))
        #POST
        response = requests.post(url, data=json.dumps(data),headers = headers)
        if response.status_code == 201:
            # マイニングも行う
            url = client.myURL + '/mine'
            headers = {"content-type":"application/json; charset=utf-8"}
            
            data= {
                "accept_id":accept_id
            }
            
            #POST
            response = requests.post(url, data=json.dumps(data),headers = headers)        
            message = 'Success add transction to blockchain network!'
            
            if View_log:
                print('マイニングリクエストが執行されました。')
                print(message)
        return render_template('message.html', title = 'result by add transaction', message = message)    
    
    
    @login_manager.user_loader
    def load_user(user_id):
            return User()
    
    
    
    
    # ------------------------------------------------------------------------ #
    # API REQUESTS
    # 自分のチェーン情報を返す - 認証不要
    # ip = request.remote_addr
    
    @app.route('/get_chain', methods=['GET'])
    def my_chain():
        
        client.check_nodes()
        # チェーンを最新の状態に更新 - todo
        
        if View_log:
            print('return myChain! requested by:' + str(request.remote_addr))
        
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
        
        if View_log:
            print('return myTransaction! requested by:' + str(request.remote_addr))
        
        response = {
            'transaction': client.transaction,
            'length': len(client.transaction),
        }
        return jsonify(response), 200
    
    # ノード応答確認  - 認証不要
    @app.route('/check_node', methods=['GET'])
    def res_node():
        if View_log:
            print('get response request! requested by:' + str(request.remote_addr))
        response = {
            'message':'Hi! myNode!'
        }
        client.myNodes = client.get_node()
        return jsonify(response), 200
    
    # ノード追加リクエスト - 認証不要
    @app.route('/add_node', methods=['POST'])
    def add_node():
        values = request.get_json()
        
        if View_log:
            print('add node request! requested by:' + str(request.remote_addr))
            
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

        if View_log:
            print('register_transaction request! requested by:' + str(request.remote_addr))
        
        accept_id = values.get('accept_id')
        if accept_id is None:
            if View_log:
                print('register_transaction accept_id is None!')            
            return "Error: Accept_idを入力してください。", 400
            
        if accept_id != client.myAccept_id:
            if View_log:
                print('register_transaction accept_id is None!')       
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