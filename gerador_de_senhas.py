import tkinter as tk
from tkinter import messagebox, simpledialog, ttk, filedialog
import random
import string
import base64
import hashlib
import os
from cryptography.fernet import Fernet

ARQUIVO_SENHAS = "senhas.dat"
ARQUIVO_HASH_SENHA_MESTRE = "senha_mestre.hash"

root = tk.Tk()
root.title("Gerador de Senhas")
root.geometry("400x450")

chave_fernet = None  # variável global para chave Fernet
senha_mestre_valida = False  # flag para indicar se senha mestre foi validada

def criar_hash_senha(senha):
    return hashlib.sha256(senha.encode()).hexdigest()

def salvar_hash_senha(hash_senha):
    with open(ARQUIVO_HASH_SENHA_MESTRE, "w") as f:
        f.write(hash_senha)

def ler_hash_senha():
    if not os.path.exists(ARQUIVO_HASH_SENHA_MESTRE):
        return None
    with open(ARQUIVO_HASH_SENHA_MESTRE, "r") as f:
        return f.read().strip()

def solicitar_criar_senha_mestre():
    while True:
        senha1 = simpledialog.askstring("Criar Senha Mestre", "Crie uma senha mestre:", show="*")
        if senha1 is None:
            return False
        if len(senha1) < 6:
            messagebox.showerror("Erro", "Senha mestre deve ter ao menos 6 caracteres.")
            continue
        senha2 = simpledialog.askstring("Confirmar Senha Mestre", "Confirme a senha mestre:", show="*")
        if senha2 is None:
            return False
        if senha1 != senha2:
            messagebox.showerror("Erro", "As senhas não coincidem. Tente novamente.")
            continue
        hash_senha = criar_hash_senha(senha1)
        salvar_hash_senha(hash_senha)
        definir_chave_fernet(senha1)
        messagebox.showinfo("Sucesso", "Senha mestre criada com sucesso.")
        return True

def solicitar_senha_mestre():
    global chave_fernet, senha_mestre_valida
    if senha_mestre_valida:
        return True

    hash_salvo = ler_hash_senha()
    if hash_salvo is None:
        return solicitar_criar_senha_mestre()

    for _ in range(3):
        senha = simpledialog.askstring("Senha Mestre", "Digite a senha mestre:", show="*")
        if senha is None:
            break
        hash_tentativa = criar_hash_senha(senha)
        if hash_tentativa == hash_salvo:
            definir_chave_fernet(senha)
            senha_mestre_valida = True
            return True
        else:
            messagebox.showerror("Erro", "Senha mestre incorreta. Tente novamente.")
    messagebox.showerror("Erro", "Falha na autenticação da senha mestre.")
    return False

def definir_chave_fernet(senha):
    global chave_fernet
    chave = base64.urlsafe_b64encode(hashlib.sha256(senha.encode()).digest())
    chave_fernet = Fernet(chave)

def avaliar_forca_senha(senha):
    pontos = 0
    if len(senha) >= 8:
        pontos += 1
    if any(c.islower() for c in senha):
        pontos += 1
    if any(c.isupper() for c in senha):
        pontos += 1
    if any(c.isdigit() for c in senha):
        pontos += 1
    if any(c in string.punctuation for c in senha):
        pontos += 1
    return pontos

def gerar_senha():
    tamanho = scale_tamanho.get()
    caracteres = ""
    if var_maiusculas.get():
        caracteres += string.ascii_uppercase
    if var_minusculas.get():
        caracteres += string.ascii_lowercase
    if var_numeros.get():
        caracteres += string.digits
    if var_simbolos.get():
        caracteres += string.punctuation

    if not caracteres:
        messagebox.showerror("Erro", "Selecione ao menos um tipo de caractere.")
        return

    senha = "".join(random.choice(caracteres) for _ in range(tamanho))
    entry_senha.delete(0, tk.END)
    entry_senha.insert(0, senha)

    pontos = avaliar_forca_senha(senha)
    barra_forca['value'] = pontos
    if pontos <= 2:
        barra_forca.configure(style="red.Horizontal.TProgressbar")
        label_forca.config(text="Fraca", fg="red")
    elif pontos == 3 or pontos == 4:
        barra_forca.configure(style="yellow.Horizontal.TProgressbar")
        label_forca.config(text="Média", fg="orange")
    else:
        barra_forca.configure(style="green.Horizontal.TProgressbar")
        label_forca.config(text="Forte", fg="green")

def copiar_senha():
    senha = entry_senha.get()
    if not senha:
        messagebox.showerror("Erro", "Nenhuma senha para copiar.")
        return
    root.clipboard_clear()
    root.clipboard_append(senha)
    messagebox.showinfo("Copiado", "Senha copiada para a área de transferência.")

def salvar_senha():
    if not solicitar_senha_mestre():
        return

    def salvar():
        descricao = entry_desc.get().strip()
        url = entry_url.get().strip()
        senha = entry_senha_salvar.get().strip()

        if not descricao or not senha:
            messagebox.showerror("Erro", "Descrição e senha são obrigatórios.")
            return

        dado = f"{descricao}: {senha} | {url}"
        dado_cripto = chave_fernet.encrypt(dado.encode())

        with open(ARQUIVO_SENHAS, "ab") as f:
            f.write(dado_cripto + b"\n")
            f.write(b"----------------------------------------\n")

        messagebox.showinfo("Salvo", "Senha salva com sucesso!\nPara ver a senha no gerenciador, abra ou atualize a tela de Gerenciar Senhas.")
        janela_salvar.destroy()

    janela_salvar = tk.Toplevel(root)
    janela_salvar.title("Salvar Senha")
    janela_salvar.geometry("350x220")
    janela_salvar.grab_set()

    tk.Label(janela_salvar, text="Descrição:").pack(anchor=tk.W, padx=10, pady=(10,0))
    entry_desc = tk.Entry(janela_salvar, width=40)
    entry_desc.pack(padx=10)

    tk.Label(janela_salvar, text="URL (opcional):").pack(anchor=tk.W, padx=10, pady=(10,0))
    entry_url = tk.Entry(janela_salvar, width=40)
    entry_url.pack(padx=10)

    tk.Label(janela_salvar, text="Senha:").pack(anchor=tk.W, padx=10, pady=(10,0))
    entry_senha_salvar = tk.Entry(janela_salvar, width=40)
    entry_senha_salvar.pack(padx=10)
    entry_senha_salvar.insert(0, entry_senha.get())

    btn_salvar = tk.Button(janela_salvar, text="Salvar", command=salvar)
    btn_salvar.pack(pady=15)

def gerenciar_senhas():
    if not solicitar_senha_mestre():
        return

    if not os.path.exists(ARQUIVO_SENHAS):
        messagebox.showwarning("Aviso", "Nenhum arquivo de senhas encontrado.")
        return

    with open(ARQUIVO_SENHAS, "rb") as f:
        linhas = f.readlines()

    senhas = []
    for linha in linhas:
        if linha.strip() == b"----------------------------------------":
            continue
        try:
            texto = chave_fernet.decrypt(linha.strip()).decode()
            partes_desc_senha_url = texto.split(": ", 1)
            descricao = partes_desc_senha_url[0]
            resto = partes_desc_senha_url[1] if len(partes_desc_senha_url) > 1 else ""
            senha_url = resto.split(" | ", 1)
            senha = senha_url[0]
            url = senha_url[1] if len(senha_url) > 1 else ""
            senhas.append({"descricao": descricao, "senha": senha, "url": url})
        except Exception:
            continue

    senhas.sort(key=lambda x: x["descricao"].lower())

    gerenciador = tk.Toplevel(root)
    gerenciador.title("Gerenciador de Senhas")
    gerenciador.geometry("520x320")

    tree = ttk.Treeview(gerenciador, columns=("descricao", "senha", "url"), show="headings")
    tree.heading("descricao", text="Descrição")
    tree.heading("senha", text="Senha")
    tree.heading("url", text="URL")
    tree.column("descricao", width=160)
    tree.column("senha", width=160)
    tree.column("url", width=180)
    tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    for item in senhas:
        tree.insert("", tk.END, values=(item["descricao"], item["senha"], item["url"]))

    def editar_senha():
        selecionado = tree.selection()
        if not selecionado:
            messagebox.showerror("Erro", "Selecione uma senha para editar.")
            return
        item = tree.item(selecionado)
        desc_atual, senha_atual, url_atual = item["values"]

        editar_win = tk.Toplevel(gerenciador)
        editar_win.title("Editar Senha")
        editar_win.geometry("350x200")
        editar_win.grab_set()

        tk.Label(editar_win, text="Descrição:").pack(anchor=tk.W, padx=10, pady=(10,0))
        entry_desc = tk.Entry(editar_win, width=40)
        entry_desc.pack(padx=10)
        entry_desc.insert(0, desc_atual)

        tk.Label(editar_win, text="URL:").pack(anchor=tk.W, padx=10, pady=(10,0))
        entry_url = tk.Entry(editar_win, width=40)
        entry_url.pack(padx=10)
        entry_url.insert(0, url_atual)

        tk.Label(editar_win, text="Senha:").pack(anchor=tk.W, padx=10, pady=(10,0))
        entry_senha_edit = tk.Entry(editar_win, width=40)
        entry_senha_edit.pack(padx=10)
        entry_senha_edit.insert(0, senha_atual)

        def salvar_edicao():
            nova_desc = entry_desc.get().strip()
            nova_url = entry_url.get().strip()
            nova_senha = entry_senha_edit.get().strip()

            if not nova_desc or not nova_senha:
                messagebox.showerror("Erro", "Descrição e senha são obrigatórios.")
                return

            tree.item(selecionado, values=(nova_desc, nova_senha, nova_url))
            atualizar_arquivo()
            editar_win.destroy()

        btn_salvar_edicao = tk.Button(editar_win, text="Salvar", command=salvar_edicao)
        btn_salvar_edicao.pack(pady=15)

    def excluir_senha():
        selecionado = tree.selection()
        if not selecionado:
            messagebox.showerror("Erro", "Selecione uma senha para excluir.")
            return
        if messagebox.askyesno("Confirmação", "Deseja realmente excluir a senha selecionada?"):
            tree.delete(selecionado)
            atualizar_arquivo()

    def nova_senha():
        def salvar_nova():
            nova_desc = entry_desc.get().strip()
            nova_url = entry_url.get().strip()
            nova_senha_valor = entry_senha_nova.get().strip()

            if not nova_desc or not nova_senha_valor:
                messagebox.showerror("Erro", "Descrição e senha são obrigatórios.")
                return

            tree.insert("", tk.END, values=(nova_desc, nova_senha_valor, nova_url))
            atualizar_arquivo()
            janela_nova.destroy()

        janela_nova = tk.Toplevel(gerenciador)
        janela_nova.title("Nova Senha")
        janela_nova.geometry("350x220")
        janela_nova.grab_set()

        tk.Label(janela_nova, text="Descrição:").pack(anchor=tk.W, padx=10, pady=(10,0))
        entry_desc = tk.Entry(janela_nova, width=40)
        entry_desc.pack(padx=10)

        tk.Label(janela_nova, text="URL (opcional):").pack(anchor=tk.W, padx=10, pady=(10,0))
        entry_url = tk.Entry(janela_nova, width=40)
        entry_url.pack(padx=10)

        tk.Label(janela_nova, text="Senha:").pack(anchor=tk.W, padx=10, pady=(10,0))
        entry_senha_nova = tk.Entry(janela_nova, width=40)
        entry_senha_nova.pack(padx=10)

        btn_salvar_nova = tk.Button(janela_nova, text="Salvar", command=salvar_nova)
        btn_salvar_nova.pack(pady=15)

    def atualizar_arquivo():
        todos_itens = tree.get_children()
        with open(ARQUIVO_SENHAS, "wb") as f:
            for item_id in todos_itens:
                desc, senha, url = tree.item(item_id)["values"]
                dado = f"{desc}: {senha} | {url}"
                dado_cripto = chave_fernet.encrypt(dado.encode())
                f.write(dado_cripto + b"\n")
                f.write(b"----------------------------------------\n")

    def exportar_senhas():
        if not tree.get_children():
            messagebox.showwarning("Aviso", "Não há senhas para exportar.")
            return
        arquivo = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Arquivo de texto", "*.txt")],
            title="Salvar arquivo de exportação"
        )
        if not arquivo:
            return
        try:
            with open(arquivo, "w", encoding="utf-8") as f:
                f.write("Senhas exportadas:\n\n")
                for item_id in tree.get_children():
                    desc, senha, url = tree.item(item_id)["values"]
                    linha = f"Descrição: {desc}\nSenha: {senha}\nURL: {url}\n\n"
                    f.write(linha)
            messagebox.showinfo("Sucesso", f"Senhas exportadas para {arquivo}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao exportar senhas:\n{e}")

    frame_botoes = tk.Frame(gerenciador)
    frame_botoes.pack(pady=5)

    btn_editar = tk.Button(frame_botoes, text="Editar", command=editar_senha)
    btn_editar.pack(side=tk.LEFT, padx=5)

    btn_excluir = tk.Button(frame_botoes, text="Excluir", command=excluir_senha)
    btn_excluir.pack(side=tk.LEFT, padx=5)

    btn_novo = tk.Button(frame_botoes, text="Nova senha", command=nova_senha)
    btn_novo.pack(side=tk.LEFT, padx=5)

    btn_exportar = tk.Button(frame_botoes, text="Exportar senhas", command=exportar_senhas)
    btn_exportar.pack(side=tk.LEFT, padx=5)
    
    def copiar_senha_selecionada():
        selecionado = tree.selection()
        if not selecionado:
            messagebox.showerror("Erro", "Selecione uma senha para copiar.")
            return
        item = tree.item(selecionado)
        senha = item["values"][1]  # índice 1 é a senha
        gerenciador.clipboard_clear()
        gerenciador.clipboard_append(senha)
        messagebox.showinfo("Copiado", "Senha copiada para a área de transferência.")

    btn_copiar_senha = tk.Button(frame_botoes, text="Copiar senha", command=copiar_senha_selecionada)
    btn_copiar_senha.pack(side=tk.LEFT, padx=5)


var_maiusculas = tk.BooleanVar(value=True)
var_minusculas = tk.BooleanVar(value=True)
var_numeros = tk.BooleanVar(value=True)
var_simbolos = tk.BooleanVar(value=True)

frame = tk.Frame(root)
frame.pack(pady=10)

tk.Label(frame, text="Tamanho da senha:").pack()
scale_tamanho = tk.Scale(frame, from_=1, to=50, orient=tk.HORIZONTAL)
scale_tamanho.set(12)
scale_tamanho.pack()

tk.Checkbutton(frame, text="Letras maiúsculas", variable=var_maiusculas).pack(anchor=tk.W)
tk.Checkbutton(frame, text="Letras minúsculas", variable=var_minusculas).pack(anchor=tk.W)
tk.Checkbutton(frame, text="Números", variable=var_numeros).pack(anchor=tk.W)
tk.Checkbutton(frame, text="Símbolos", variable=var_simbolos).pack(anchor=tk.W)

btn_gerar = tk.Button(frame, text="Gerar senha", command=gerar_senha)
btn_gerar.pack(pady=5)

entry_senha = tk.Entry(frame, width=40)
entry_senha.pack(pady=5)

style = ttk.Style()
style.theme_use('default')
style.configure("red.Horizontal.TProgressbar", troughcolor='gray', background='red')
style.configure("yellow.Horizontal.TProgressbar", troughcolor='gray', background='orange')
style.configure("green.Horizontal.TProgressbar", troughcolor='gray', background='green')

label_forca = tk.Label(frame, text="Força da senha: ")
label_forca.pack(pady=(10, 0))
barra_forca = ttk.Progressbar(frame, length=200, maximum=5, style="red.Horizontal.TProgressbar")
barra_forca.pack()

btn_copiar = tk.Button(frame, text="Copiar senha", command=copiar_senha)
btn_copiar.pack(pady=2)

btn_salvar = tk.Button(frame, text="Salvar senha", command=salvar_senha)
btn_salvar.pack(pady=2)

btn_gerenciar = tk.Button(frame, text="Gerenciar senhas", command=gerenciar_senhas)
btn_gerenciar.pack(pady=2)

# Função para mostrar informações do desenvolvedor
def mostrar_sobre():
    messagebox.showinfo("Sobre", "Desenvolvedor: Erik Vasconcelos\nEmail: erikvasconcelosprogramador@gmail.com")

# Criar menu principal com 'Ajuda' -> 'Sobre'
menu_principal = tk.Menu(root)
root.config(menu=menu_principal)

menu_ajuda = tk.Menu(menu_principal, tearoff=0)
menu_ajuda.add_command(label="Sobre", command=mostrar_sobre)

menu_principal.add_cascade(label="Ajuda", menu=menu_ajuda)

if not solicitar_senha_mestre():
    messagebox.showerror("Erro", "Não foi possível autenticar. O programa será encerrado.")
    root.destroy()
else:
    root.mainloop()