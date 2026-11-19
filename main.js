'use strict';
const form=document.querySelector('#form');
const input=document.querySelector('#password');
const button=document.querySelector('#unlock');
const viewer=document.querySelector('#viewer');
const login=document.querySelector('#login');
const contentArea=document.querySelector('#contentArea');
const textDecoder=new TextDecoder('utf-8',{fatal:true});
const fromBase64=(value)=>Uint8Array.from(atob(value),character=>character.charCodeAt(0));

async function decrypt(password,payload){
  if(payload.version!==1 || payload.algorithm!=='AES-256-GCM' || payload.kdf!=='PBKDF2-SHA256'
    || !Number.isInteger(payload.iterations) || payload.iterations<100000 || payload.iterations>2000000){
    throw new Error('bad format');
  }
  const master=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveKey']);
  const key=await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:fromBase64(payload.salt),iterations:payload.iterations},master,{name:'AES-GCM',length:256},false,['decrypt']);
  const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:fromBase64(payload.iv)},key,fromBase64(payload.ciphertext));
  const content=JSON.parse(textDecoder.decode(plain));
  if(typeof content.body!=='string' || typeof content.css!=='string')throw new Error('invalid contents');
  return content;
}

form.addEventListener('submit',async(event)=>{
  event.preventDefault();
  const password=input.value;
  if(!password)return;
  button.disabled=true;
  try{
    const response=await fetch('./content.json',{cache:'no-store'});
    if(!response.ok)throw new Error('missing file');
    const payload=await response.json();
    const page=await decrypt(password,payload);
    const iframeHTML='<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><style>'+page.css+'</style></head><body>'+page.body+'</body></html>';
    viewer.srcdoc=iframeHTML;
    input.value='';
    login.style.display='none';
    contentArea.style.display='flex';
  }catch(e){
    input.select();
  }finally{
    button.disabled=false;
  }
});

document.querySelector('#lock').addEventListener('click',()=>{
  viewer.srcdoc='';
  contentArea.style.display='none';
  login.style.display='grid';
  input.type='password';
  input.value='';
  input.focus();
});
