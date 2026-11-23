async function save(formData) { 'use server'; console.log('save', formData.get('name')); }
export default function Page(){ return (<form action={save}><input name="name"/><button>ok</button></form>); }
