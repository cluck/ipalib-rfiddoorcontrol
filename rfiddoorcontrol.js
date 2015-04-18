define([
    'freeipa/phases',
    'freeipa/reg',
    'freeipa/rpc',
    'freeipa/ipa',
    'freeipa/user'],
    function(phases, reg, rpc, IPA, user_mod) {

function get_item_by_attrval(array, attr, value) {
    for (var i=0, l=array.length; i<l; i++) {
        if (array[i][attr] === value) return array[i];
    }
    return null;
}

var exp = IPA.rfiddoorcontrol = {};

exp.add_rfid_pre_op = function() {
    var facet = get_item_by_attrval(user_mod.entity_spec.facets, '$type', 'details');
    var section = get_item_by_attrval(facet.sections, 'name', 'identity');
    section.fields.push({
        name: 'rfidkey',
        $type: 'multivalued',
        label: 'RFID Key'
    });
    section.fields.push({
        name: 'rfiddooraccess',
        $type: 'multivalued',
        label: 'RFID Door Access'
    });
    return true;
}

exp.add_rfid_actions = function() {
    reg.action.register('user_addrfid', exp.user_addrfid);

    var facet = get_item_by_attrval(user_mod.entity_spec.facets, '$type', 'details');
    var section = get_item_by_attrval(facet.sections, 'name', 'identity');

    facet.actions.push({
        $factory: IPA.object_action,
        name: 'user_addrfid',
        method: 'addrfid',
        label: '@i18n:actions.user_addrfid',
        needs_confirm: false
    });
    facet.header_actions.push('user_addrfid');

    facet.actions.push({
        $factory: IPA.object_action,
        name: 'user_delrfid',
        method: 'delrfid',
        label: '@i18n:actions.user_delrfid',
        needs_confirm: true
    });
    facet.header_actions.push('user_delrfid');

    return true;
};

phases.on('registration', exp.add_rfid_actions);
phases.on('customization', exp.add_rfid_pre_op);

return exp;
}); 

