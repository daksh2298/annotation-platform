from project import app

if __name__=='__main__':
    app.run(debug=True,
            host="0.0.0.0",
            port=os.environ.get('PORT', 8080))