import streamlit as st
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
from snowflake.snowpark import Session
from snowflake.snowpark.context import get_active_session

# 最初にページ設定
st.set_page_config(
    page_title="ユーザ情報",
    layout="wide",
    initial_sidebar_state="expanded",
)

# カスタムCSSで余白の調整
st.markdown(
    """
    <style>
    body {
        margin-top: 10px;  /* 上の余白を狭く */
        margin-bottom: 50px;  /* 下の余白を広く */
    }
    .stButton>button {
        margin-top: 10px;  /* ボタン間の余白 */
    }
    .rsa-warning-blue {
        background-color: #cce5ff;  /* 青 */
        padding: 10px;
        border-radius: 5px;
        color: #004085;
        font-size: 16px;
    }
    .rsa-warning-green {
        background-color: #d4edda;  /* 黄緑 */
        padding: 10px;
        border-radius: 5px;
        color: #155724;
        font-size: 16px;
    }
    .rsa-warning-yellow {
        background-color: #fff3cd;  /* 黄色 */
        padding: 10px;
        border-radius: 5px;
        color: #856404;
        font-size: 16px;
    }
    .spacer {
        height: 20px;  /* 余白を追加 */
    }
    </style>
    """, unsafe_allow_html=True
)

# Snowflake接続をセッションから取得する
def get_snowflake_connection():
    return get_active_session()

# Snowflake接続を初期化
if 'snowflake_connection' not in st.session_state:
    st.session_state.snowflake_connection = get_snowflake_connection()

# ユーザーが存在するか確認し、RSA公開鍵が登録されているかも確認
def check_user_exists_and_rsa_key(user_name):
    session = st.session_state.snowflake_connection
    query = f"""
    select HAS_RSA_PUBLIC_KEY from snowflake.account_usage.users where name = '{user_name.upper()}'
    """
    re = session.sql(query).collect()
    if len(re) > 0:
        return re[0][0]  # HAS_RSA_PUBLIC_KEY の値 (TRUE or FALSE)
    else:
        return None

# SnowflakeユーザーのRSA公開鍵を設定する関数
def exe_set_user_key(selected_user, public_key):
    try:
        query = f"ALTER USER {selected_user} SET RSA_PUBLIC_KEY = '{public_key}'"
        st.session_state.snowflake_connection.sql(query).collect()
        st.info(f"ユーザ {selected_user} のPublic Keyを設定しました", icon="🔑")
        # 成功した場合のエラーメッセージをリセット
        st.session_state.error_message = None
    except Exception as e:
        # エラー発生時、エラーメッセージをセッションに保存
        st.session_state.error_message = f"🚨 エラーが発生しました。Public Keyは設定されていません: {str(e)}"

# SnowflakeユーザーのRSA公開鍵を削除する関数
def exe_remove_user_key(selected_user):
    try:
        # ユーザのRSA公開鍵を削除するSQLクエリを変更
        query = f"ALTER USER {selected_user} UNSET RSA_PUBLIC_KEY"
        st.session_state.snowflake_connection.sql(query).collect()
        st.info(f"ユーザ {selected_user} のPublic Keyを削除しました(反映には時間がかかります)", icon="🔑")
        # 成功した場合のエラーメッセージをリセット
        st.session_state.error_message = None
        return True  # 公開鍵削除成功
    except Exception as e:
        # エラー発生時、エラーメッセージをセッションに保存
        st.session_state.error_message = f"🚨 エラーが発生しました。Public Keyは削除されていません: {str(e)}"
        return False  # 公開鍵削除失敗

# ファイルダウンロード用のヘルパー関数
def get_file(label, data, file_name):
    st.download_button(
        label=label,
        data=data,
        file_name=file_name,
        mime="application/x-pem-file"
    )

# Streamlit UI設定
st.title("👤 ユーザ情報の更新")
st.divider()
st.header("🔐 key-pair認証の設定", divider="rainbow")

if 'selected_column' not in st.session_state:
    st.session_state.selected_column = None

# ユーザー入力
selected_user = st.text_input("ユーザ名を入力してください:")

# 入力されたユーザ名を確認
if selected_user:
    HAS_RSA_PUBLIC_KEY = check_user_exists_and_rsa_key(selected_user)
    if HAS_RSA_PUBLIC_KEY is not None:
        if HAS_RSA_PUBLIC_KEY == True:  # ユーザーに公開鍵がすでに登録されている
            # 黄緑色の背景
            st.markdown(f'<div class="rsa-warning-green">ユーザ {selected_user} はRSA公開鍵をすでに持っています。更新作業を行います。</div>', unsafe_allow_html=True)

            # 余白を追加
            st.markdown('<div class="spacer"></div>', unsafe_allow_html=True)

        else:  # HAS_RSA_PUBLIC_KEY が FALSE の場合
            # 青色の背景
            st.markdown(f'<div class="rsa-warning-blue">ユーザ {selected_user} はRSA公開鍵を持っていません。新規登録を行います。</div>', unsafe_allow_html=True)

            # 余白を追加
            st.markdown('<div class="spacer"></div>', unsafe_allow_html=True)

        # 公開鍵および秘密鍵の新規作成・更新ボタン
        with st.expander('公開鍵および秘密鍵の新規作成・更新'):
            st.header("新しい鍵ペアを生成して設定します", divider="blue")
            passphrase = st.text_input("秘密鍵を暗号化するためのパスフレーズを入力してください:", type="password")
            
            if st.button("公開鍵および秘密鍵を新規作成・更新する"):
                if not passphrase:
                    st.error("パスフレーズを入力してください")
                else:
                    # 新たに鍵を生成する
                    key = rsa.generate_private_key(
                        key_size=2048,
                        public_exponent=65537,
                        backend=default_backend()
                    )

                    # パスフレーズで秘密鍵を暗号化
                    encrypted_private_key = key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
                    )

                    gen_public_key = key.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )

                    # セッションに鍵を保存
                    st.session_state.generated_private_key = encrypted_private_key
                    st.session_state.generated_public_key = gen_public_key
                    st.session_state.generated_key = key  # ここで `key` オブジェクトも保存

                    # 公開鍵をSnowflakeユーザーに設定
                    if 'generated_key' in st.session_state and st.session_state.generated_key is not None:
                        gen_public_key_der = base64.b64encode(
                            st.session_state.generated_key.public_key().public_bytes(
                                serialization.Encoding.DER,
                                serialization.PublicFormat.SubjectPublicKeyInfo
                            )
                        ).decode('utf-8')

                        exe_set_user_key(selected_user, gen_public_key_der)

                    # 再確認フラグをリセット
                    st.session_state.confirm_key_generation = False

            # エラーメッセージの表示 (key-pair生成ボタンの直下に表示)
            if 'error_message' in st.session_state and st.session_state.error_message:
                st.error(st.session_state.error_message)

            # 生成された鍵を表示
            if 'generated_private_key' in st.session_state and 'generated_public_key' in st.session_state:
                # 鍵が生成されている場合のみ表示
                if st.session_state.generated_private_key is not None:
                    st.text_area("秘密鍵", st.session_state.generated_private_key.decode(encoding="utf-8"), height=200)
                    get_file("Download private key", st.session_state.generated_private_key, f"private_{selected_user}.key")

                if st.session_state.generated_public_key is not None:
                    st.text_area("公開鍵", st.session_state.generated_public_key.decode(encoding="utf-8"), height=250)
                    get_file("Download public key", st.session_state.generated_public_key, f"public_{selected_user}.pub")

        # 公開鍵の削除機能
        with st.expander("公開鍵の削除"):
            if st.button(f"{selected_user} の公開鍵を削除する"):
                if exe_remove_user_key(selected_user):
                    st.session_state.key_deleted = True  # 公開鍵削除成功フラグを設定

    else:
        # 黄色の背景 (ユーザが存在しない場合)
        st.markdown(f'<div class="rsa-warning-yellow">ユーザ {selected_user} は存在しません。再度確認してください。</div>', unsafe_allow_html=True)
